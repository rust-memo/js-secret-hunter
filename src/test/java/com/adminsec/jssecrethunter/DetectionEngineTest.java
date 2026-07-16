package com.adminsec.jssecrethunter;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DetectionEngineTest {
    private final RulePackManager rules = new RulePackManager();
    private final DetectionEngine engine = new DetectionEngine(rules);

    @Test
    void detectsProviderSecretAndMasksIt() {
        String value = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        List<Finding> findings = scan("const api = '" + value + "';");
        Finding finding = findings.stream().filter(f -> f.ruleId().equals("openai-api-key")).findFirst().orElseThrow();
        assertNotEquals(value, finding.maskedValue());
        assertTrue(finding.maskedValue().startsWith("sk-p"));
        assertEquals(64, finding.valueFingerprint().length());
    }

    @Test
    void ignoresGenericPlaceholdersButFindsRealLookingAssignments() {
        assertTrue(scan("const api_key = 'your_api_key'; const password = 'changeme';").isEmpty());
        List<Finding> findings = scan("const client_secret = '9faD3kLmP0qRs8TuV4wXy7ZaBcDeFgHi';");
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("generic-api-secret")));
    }

    @Test
    void detectsAdministrativeAndGraphqlRoutesSeparatelyFromSecrets() {
        List<Finding> findings = scan("const a='/admin/users'; const gql='/graphql';");
        assertTrue(findings.stream().anyMatch(f -> f.kind() == FindingKind.ENDPOINT && f.ruleId().equals("admin-debug-route")));
        assertTrue(findings.stream().anyMatch(f -> f.kind() == FindingKind.ENDPOINT && f.ruleId().equals("graphql-endpoint")));
    }

    @Test
    void scansEscapedJavaScriptStrings() {
        String script = "const cfg=\"client_secret\\u003d\\\"9faD3kLmP0qRs8TuV4wXy7ZaBcDeFgHi\\\"\";";
        assertTrue(scan(script).stream().anyMatch(f -> f.ruleId().equals("generic-api-secret")));
    }

    @Test
    void findsLinkFinderStyleEndpointsWithoutDuplicatingSpecificRules() {
        List<Finding> findings = scan("const users='/users/profile?active=true'; "
                + "const docs=`https://api.example.com/reference`; const api='/api/v1/accounts';");
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("linkfinder-endpoint")
                && f.rawValue().equals("/users/profile?active=true")));
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("linkfinder-endpoint")
                && f.rawValue().equals("https://api.example.com/reference")));
        assertEquals(1, findings.stream().filter(f -> f.rawValue().equals("/api/v1/accounts")).count());
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("api-endpoint")
                && f.rawValue().equals("/api/v1/accounts")));
    }

    @Test
    void decodesBase64UrlContent() {
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "client_secret=\"9faD3kLmP0qRs8TuV4wXy7ZaBcDeFgHi\"".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(scan("const payload='" + encoded + "';").stream()
                .anyMatch(f -> f.ruleId().equals("generic-api-secret")));
    }

    @Test
    void detectsCalibratedClientSideVulnerabilityCandidates() {
        String script = """
                panel.innerHTML = userInput;
                eval(payload);
                window.location.href = new URLSearchParams(location.search).get('next');
                parent.postMessage(message, '*');
                const agent = { rejectUnauthorized: false };
                localStorage.setItem('access_token', token);
                merge(target, source.__proto__);
                const socket = 'ws://socket.example.test/chat';
                """;
        List<Finding> findings = scan(script);
        for (String id : List.of("dom-xss-html-sink", "dynamic-code-execution-sink", "client-open-redirect-flow",
                "wildcard-postmessage-target", "disabled-tls-verification", "sensitive-browser-storage",
                "prototype-pollution-dangerous-key", "cleartext-websocket-transport")) {
            assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals(id)), "missing " + id);
        }
        assertTrue(findings.stream().filter(f -> f.ruleId().contains("sink"))
                .allMatch(f -> f.kind() == FindingKind.VULNERABILITY));
    }

    @Test
    void redactsSensitiveValuesFromAllPreviewsAndEndpointPresentation() {
        String secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        String querySecret = "supersecretvalue123";
        List<Finding> findings = scan("const key='" + secret + "'; const url='/api/users?token=" + querySecret + "';");
        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().noneMatch(f -> f.preview().contains(secret)));
        Finding endpoint = findings.stream().filter(f -> f.ruleId().equals("api-endpoint")).findFirst().orElseThrow();
        assertFalse(endpoint.maskedValue().contains(querySecret));
        assertTrue(endpoint.maskedValue().contains("token=[REDACTED]"));
    }

    @Test
    void honorsSensitiveConfigurationFlagAndOriginalLineForDecodedStrings() {
        String dsn = "https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/42";
        Finding sentry = scan("const sentry='" + dsn + "';").stream()
                .filter(f -> f.ruleId().equals("sentry-dsn")).findFirst().orElseThrow();
        assertNotEquals(dsn, sentry.maskedValue());

        String script = "first();\nsecond();\nconst cfg=\"client_secret\\u003d\\\"9faD3kLmP0qRs8TuV4wXy7ZaBcDeFgHi\\\"\";";
        List<Finding> decoded = scan(script).stream()
                .filter(f -> f.ruleId().equals("generic-api-secret")).toList();
        assertFalse(decoded.isEmpty());
        assertTrue(decoded.stream().allMatch(f -> f.line() == 3));
    }

    private List<Finding> scan(String body) {
        HttpRequest request = mock(HttpRequest.class); HttpResponse response = mock(HttpResponse.class);
        HttpService service = mock(HttpService.class);
        when(request.url()).thenReturn("https://app.test/app.js"); when(request.method()).thenReturn("GET");
        when(request.httpService()).thenReturn(service); when(service.host()).thenReturn("app.test");
        return engine.scan(body, request.url(), "https://app.test/", List.of("https://app.test/", request.url()), request, response);
    }
}
