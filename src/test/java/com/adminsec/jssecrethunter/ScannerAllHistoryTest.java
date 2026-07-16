package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.adminsec.jssecrethunter.model.Confidence;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.adminsec.jssecrethunter.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScannerAllHistoryTest {
    @Test
    void scansAnOutOfScopeJavaScriptResponseFromHistoryWithoutSendingANetworkRequest() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        Proxy proxy = mock(Proxy.class);
        when(api.proxy()).thenReturn(proxy);
        when(api.logging()).thenReturn(mock(Logging.class));

        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://outside.test/app.js");
        when(request.isInScope()).thenReturn(false);
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(48);
        when(response.body()).thenReturn(body);
        when(response.bodyToString()).thenReturn("const token = 'sensitive-history-value-123456';");
        when(response.statusCode()).thenReturn((short) 200);
        when(response.hasHeader("Content-Type")).thenReturn(true);
        when(response.headerValue("Content-Type")).thenReturn("application/javascript");

        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        when(item.hasResponse()).thenReturn(true);
        when(proxy.history(any(ProxyHistoryFilter.class))).thenAnswer(invocation -> {
            ProxyHistoryFilter filter = invocation.getArgument(0);
            return filter.matches(item) ? List.of(item) : List.of();
        });

        String raw = "sensitive-history-value-123456";
        Finding finding = new Finding("history-secret", "History secret", FindingKind.SECRET,
                Severity.HIGH, Confidence.HIGH, request.url(), request.url(), List.of(request.url()),
                1, 15, 15 + raw.length(), "token", raw, request, response);
        DetectionEngine detector = mock(DetectionEngine.class);
        when(detector.scan(anyString(), anyString(), anyString(), anyList(), any(), any())).thenReturn(List.of(finding));
        HunterRepository repository = new HunterRepository(null);
        ScannerService scanner = new ScannerService(api, new HunterConfig(), repository, detector);

        try {
            scanner.scanHistory();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (repository.findingCount() != 1 && System.nanoTime() < deadline) Thread.sleep(20);
            assertEquals(1, repository.findingCount());
            assertTrue(repository.snapshot().findings().get(0).assetUrl().endsWith("/app.js"));
            verify(api, never()).http();
        } finally { scanner.shutdown(); }
    }
}
