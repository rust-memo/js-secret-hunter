package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.adminsec.jssecrethunter.model.Confidence;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.adminsec.jssecrethunter.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScannerLifecycleTest {
    @Test
    void clearPreventsInProgressOldGenerationFromRestoringResults() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.logging()).thenReturn(mock(Logging.class));
        HunterConfig config = new HunterConfig();
        HunterRepository repository = new HunterRepository(null);
        DetectionEngine detector = mock(DetectionEngine.class);
        ScannerService scanner = new ScannerService(api, config, repository, detector);
        HttpRequest request = request();
        HttpResponse response = response();
        CountDownLatch detectorEntered = new CountDownLatch(1);
        CountDownLatch releaseDetector = new CountDownLatch(1);
        CountDownLatch idleAfterCancel = new CountDownLatch(1);
        AtomicBoolean cancelled = new AtomicBoolean();
        Finding finding = finding(request, response);
        doAnswer(invocation -> {
            detectorEntered.countDown();
            assertTrue(releaseDetector.await(5, TimeUnit.SECONDS));
            return List.of(finding);
        }).when(detector).scan(anyString(), anyString(), anyString(), anyList(), any(), any());
        scanner.stateListener(state -> {
            if (cancelled.get() && state.phase() == ScanState.Phase.IDLE) idleAfterCancel.countDown();
        });
        try {
            scanner.observe(request, response, null);
            assertTrue(detectorEntered.await(5, TimeUnit.SECONDS));
            cancelled.set(true);
            scanner.clearScanState();
            releaseDetector.countDown();
            assertTrue(idleAfterCancel.await(5, TimeUnit.SECONDS));
            assertTrue(repository.snapshot().findings().isEmpty());
            assertTrue(repository.snapshot().assets().isEmpty());
        } finally {
            releaseDetector.countDown();
            scanner.shutdown();
        }
    }

    private static HttpRequest request() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn("https://app.test/config.json");
        when(request.isInScope()).thenReturn(true);
        return request;
    }

    private static HttpResponse response() {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(body.length()).thenReturn(64);
        when(response.body()).thenReturn(body);
        when(response.bodyToString()).thenReturn("{\"client_secret\":\"9faD3kLmP0qRs8TuV4wXy7ZaBcDeFgHi\"}");
        when(response.statusCode()).thenReturn((short) 200);
        when(response.hasHeader("Content-Type")).thenReturn(true);
        when(response.headerValue("Content-Type")).thenReturn("application/json");
        return response;
    }

    private static Finding finding(HttpRequest request, HttpResponse response) {
        String raw = "9faD3kLmP0qRs8TuV4wXy7ZaBcDeFgHi";
        return new Finding("generic-api-secret", "Generic API secret", FindingKind.SECRET, Severity.HIGH, Confidence.MEDIUM,
                request.url(), request.url(), List.of(request.url()), 1, 18, 18 + raw.length(), "masked", raw, request, response);
    }
}
