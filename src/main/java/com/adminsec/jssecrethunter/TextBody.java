package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

public final class TextBody {
    private TextBody() {}

    public static String decode(HttpResponse response, int limit) {
        if (response == null || response.body() == null || response.body().length() == 0 || response.body().length() > limit) return null;
        String header = response.hasHeader("Content-Encoding") ? response.headerValue("Content-Encoding") : "";
        String encoding = header == null ? "" : header.trim().toLowerCase(Locale.ROOT);
        if (encoding.isBlank() || encoding.equals("identity")) return response.bodyToString();
        if (!encoding.equals("gzip") && !encoding.equals("x-gzip") && !encoding.equals("deflate")) return null;
        try (ByteArrayInputStream input = new ByteArrayInputStream(response.body().getBytes());
             var decoded = encoding.contains("gzip") ? new GZIPInputStream(input) : new InflaterInputStream(input);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            for (int read; (read = decoded.read(buffer)) != -1;) {
                total += read;
                if (total > limit) return null;
                output.write(buffer, 0, read);
            }
            return output.toString(StandardCharsets.UTF_8);
        } catch (IOException malformed) { return null; }
    }
}
