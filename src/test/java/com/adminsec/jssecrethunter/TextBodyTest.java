package com.adminsec.jssecrethunter;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TextBodyTest {
    @Test
    void decodesGzipWithinLimitAndRejectsUnsupportedEncoding() throws Exception {
        String script = "const secret='value';";
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) { gzip.write(script.getBytes(StandardCharsets.UTF_8)); }
        HttpResponse response = mock(HttpResponse.class); ByteArray body = mock(ByteArray.class);
        when(response.body()).thenReturn(body); when(body.length()).thenReturn(output.size()); when(body.getBytes()).thenReturn(output.toByteArray());
        when(response.hasHeader("Content-Encoding")).thenReturn(true); when(response.headerValue("Content-Encoding")).thenReturn("gzip");
        assertEquals(script, TextBody.decode(response, 1024));
        when(response.headerValue("Content-Encoding")).thenReturn("br");
        assertNull(TextBody.decode(response, 1024));
    }
}
