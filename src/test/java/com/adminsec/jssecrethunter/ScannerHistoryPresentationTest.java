package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScannerHistoryPresentationTest {
    @Test
    void cleansOldExtensionNotesEvenWhenTheTrafficIsOutsideTargetScope() throws Exception {
        MontoyaApi api = mock(MontoyaApi.class);
        Proxy proxy = mock(Proxy.class);
        when(api.proxy()).thenReturn(proxy);
        when(api.logging()).thenReturn(mock(Logging.class));
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpRequest request = mock(HttpRequest.class);
        when(item.finalRequest()).thenReturn(request);
        when(item.hasResponse()).thenReturn(true);
        when(request.isInScope()).thenReturn(false);
        Annotations annotations = mock(Annotations.class);
        AtomicReference<String> notes = new AtomicReference<>("analyst note | [JS Secret Hunter] HIGH - 2 candidate(s)");
        when(item.annotations()).thenReturn(annotations);
        when(annotations.hasNotes()).thenAnswer(ignored -> !notes.get().isBlank());
        when(annotations.notes()).thenAnswer(ignored -> notes.get());
        doAnswer(invocation -> { notes.set(invocation.getArgument(0)); return null; }).when(annotations).setNotes(any());
        when(proxy.history(any(ProxyHistoryFilter.class))).thenAnswer(invocation -> {
            ProxyHistoryFilter filter = invocation.getArgument(0);
            return filter.matches(item) ? List.of(item) : List.of();
        });
        HunterConfig config = new HunterConfig();
        config.scanScope(ScanScope.TARGET_SCOPE);
        ScannerService scanner = new ScannerService(api, config, new HunterRepository(null), mock(DetectionEngine.class));
        CountDownLatch complete = new CountDownLatch(1);
        scanner.stateListener(state -> {
            if (state.message().startsWith("No in-scope history responses")) complete.countDown();
        });
        try {
            scanner.scanHistory();
            assertTrue(complete.await(5, TimeUnit.SECONDS));
            assertEquals("analyst note", notes.get());
        } finally { scanner.shutdown(); }
    }
}
