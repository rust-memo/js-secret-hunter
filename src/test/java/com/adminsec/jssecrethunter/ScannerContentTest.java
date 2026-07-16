package com.adminsec.jssecrethunter;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScannerContentTest {
    private final HttpRequest request = mock(HttpRequest.class);

    @Test
    void classifiesJsonXmlTextAndBinaryResponses() {
        assertEquals(ContentClass.JSON, classify("application/problem+json", "https://app.test/api"));
        assertEquals(ContentClass.XML, classify("application/xml; charset=utf-8", "https://app.test/feed"));
        assertEquals(ContentClass.TEXT, classify("text/css", "https://app.test/styles"));
        assertEquals(ContentClass.JAVASCRIPT, classify("application/octet-stream", "https://app.test/app.js"));
        assertEquals(ContentClass.SOURCE_MAP, classify("application/json", "https://app.test/app.js.map"));
        assertEquals(ContentClass.BINARY, classify("application/octet-stream", "https://app.test/image"));
    }

    @Test
    void removesOnlyExtensionOwnedHistoryNoteSegments() {
        assertEquals("analyst note", ScannerService.stripHunterNote(
                "analyst note | [JS Secret Hunter] HIGH - 3 candidate(s)"));
        assertEquals("before | after", ScannerService.stripHunterNote(
                "before | [JS Secret Hunter] MEDIUM - 1 candidate(s) | after"));
        assertEquals("", ScannerService.stripHunterNote("[JS Secret Hunter] INFO - 2 candidate(s)"));
    }

    @Test
    void responseFingerprintChangesForSameLengthContentAndMetadata() {
        HttpResponse first = response("application/javascript", "const a=1;");
        HttpResponse second = response("application/javascript", "const b=2;");
        HttpResponse otherType = response("text/plain", "const a=1;");
        assertNotEquals(ScannerService.responseFingerprint(first), ScannerService.responseFingerprint(second));
        assertNotEquals(ScannerService.responseFingerprint(first), ScannerService.responseFingerprint(otherType));
    }

    private ContentClass classify(String contentType, String url) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.hasHeader("Content-Type")).thenReturn(true);
        when(response.headerValue("Content-Type")).thenReturn(contentType);
        return ScannerService.classify(request, response, url);
    }

    private static HttpResponse response(String contentType, String bodyText) {
        HttpResponse response = mock(HttpResponse.class);
        ByteArray body = mock(ByteArray.class);
        when(body.getBytes()).thenReturn(bodyText.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(response.body()).thenReturn(body);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.hasHeader("Content-Type")).thenReturn(true);
        when(response.headerValue("Content-Type")).thenReturn(contentType);
        return response;
    }
}
