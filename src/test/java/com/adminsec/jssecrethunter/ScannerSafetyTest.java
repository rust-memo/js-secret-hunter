package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ScannerSafetyTest {
    @Test
    void originIncludesSchemeHostAndEffectivePort() {
        assertTrue(ScannerService.sameOrigin("https://app.test/a.js", "https://app.test/page"));
        assertTrue(ScannerService.sameOrigin("https://app.test:443/a.js", "https://app.test/page"));
        assertFalse(ScannerService.sameOrigin("http://app.test/a.js", "https://app.test/page"));
        assertFalse(ScannerService.sameOrigin("https://cdn.test/a.js", "https://app.test/page"));
        assertFalse(ScannerService.sameOrigin("https://app.test:8443/a.js", "https://app.test/page"));
    }

    @Test
    void credentialsAreInheritedOnlyForSameOrigin() {
        HttpRequest parent = mock(HttpRequest.class); HttpRequest target = mock(HttpRequest.class);
        HttpHeader cookie = header("Cookie", "sid=secret"); HttpHeader auth = header("Authorization", "Bearer secret");
        HttpHeader agent = header("User-Agent", "Browser");
        when(parent.url()).thenReturn("https://app.test/page"); when(parent.headers()).thenReturn(List.of(cookie, auth, agent));
        when(target.withUpdatedHeader(anyString(), anyString())).thenReturn(target);
        try (var staticRequest = mockStatic(HttpRequest.class)) {
            staticRequest.when(() -> HttpRequest.httpRequestFromUrl(anyString())).thenReturn(target);
            ScannerService.requestFor("https://app.test/app.js", parent);
            verify(target).withUpdatedHeader("Cookie", "sid=secret");
            verify(target).withUpdatedHeader("Authorization", "Bearer secret");
            clearInvocations(target);
            ScannerService.requestFor("https://cdn.test/app.js", parent);
            verify(target, never()).withUpdatedHeader(eq("Cookie"), anyString());
            verify(target, never()).withUpdatedHeader(eq("Authorization"), anyString());
            verify(target).withUpdatedHeader("User-Agent", "Browser");
        }
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader header = mock(HttpHeader.class); when(header.name()).thenReturn(name); when(header.value()).thenReturn(value); return header;
    }
}
