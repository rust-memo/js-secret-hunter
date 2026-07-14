package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    private ContentClass classify(String contentType, String url) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.hasHeader("Content-Type")).thenReturn(true);
        when(response.headerValue("Content-Type")).thenReturn(contentType);
        return ScannerService.classify(request, response, url);
    }
}
