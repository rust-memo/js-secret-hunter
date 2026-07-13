package com.adminsec.jssecrethunter;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import org.junit.jupiter.api.Test;

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

    private List<Finding> scan(String body) {
        HttpRequest request = mock(HttpRequest.class); HttpResponse response = mock(HttpResponse.class);
        HttpService service = mock(HttpService.class);
        when(request.url()).thenReturn("https://app.test/app.js"); when(request.method()).thenReturn("GET");
        when(request.httpService()).thenReturn(service); when(service.host()).thenReturn("app.test");
        return engine.scan(body, request.url(), "https://app.test/", List.of("https://app.test/", request.url()), request, response);
    }
}
