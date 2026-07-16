package com.adminsec.jssecrethunter.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

public final class Finding {
    private final String fingerprint;
    private final Instant discoveredAt = Instant.now();
    private final String ruleId;
    private final String ruleName;
    private final FindingKind kind;
    private final Severity severity;
    private final Confidence confidence;
    private final String assetUrl;
    private final String rootUrl;
    private final List<String> discoveryChain;
    private final int line;
    private final int start;
    private final int end;
    private volatile String preview;
    private final String rawValue;
    private final boolean sensitiveValue;
    private final String description;
    private final String remediation;
    private final HttpRequest request;
    private final HttpResponse response;
    private volatile ReviewStatus reviewStatus = ReviewStatus.NEEDS_REVIEW;
    private volatile boolean published;

    public Finding(String ruleId, String ruleName, FindingKind kind, Severity severity, Confidence confidence,
                   String assetUrl, String rootUrl, List<String> discoveryChain, int line, int start, int end,
                   String preview, String rawValue, HttpRequest request, HttpResponse response) {
        this(ruleId, ruleName, kind, severity, confidence, assetUrl, rootUrl, discoveryChain, line, start, end,
                preview, rawValue, defaultSensitiveValue(kind), "", "", request, response);
    }

    public Finding(String ruleId, String ruleName, FindingKind kind, Severity severity, Confidence confidence,
                   String assetUrl, String rootUrl, List<String> discoveryChain, int line, int start, int end,
                   String preview, String rawValue, boolean sensitiveValue, String description, String remediation,
                   HttpRequest request, HttpResponse response) {
        this.ruleId = Objects.requireNonNull(ruleId);
        this.ruleName = Objects.requireNonNull(ruleName);
        this.kind = Objects.requireNonNull(kind);
        this.severity = Objects.requireNonNull(severity);
        this.confidence = Objects.requireNonNull(confidence);
        this.assetUrl = Objects.requireNonNull(assetUrl);
        this.rootUrl = Objects.requireNonNull(rootUrl);
        this.discoveryChain = List.copyOf(discoveryChain);
        this.line = line;
        this.start = start;
        this.end = end;
        this.preview = preview == null ? "" : preview;
        this.rawValue = rawValue == null ? "" : rawValue;
        this.sensitiveValue = sensitiveValue;
        this.description = description == null ? "" : description;
        this.remediation = remediation == null ? "" : remediation;
        this.request = Objects.requireNonNull(request);
        this.response = response;
        this.fingerprint = sha256(assetUrl + "\n" + ruleId + "\n" + start + "\n" + sha256(this.rawValue));
    }

    public static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    public String maskedValue() {
        if (rawValue.isBlank()) return "";
        if (!sensitiveValue && (kind == FindingKind.ENDPOINT || kind == FindingKind.CONFIGURATION
                || kind == FindingKind.VULNERABILITY)) return redactUrlValue(rawValue);
        return mask(rawValue);
    }

    public static String redactUrlValue(String value) {
        if (value == null || value.isBlank()) return value == null ? "" : value;
        String redacted = Pattern.compile("((?:https?|wss?)://)[^\\s/@]+@", Pattern.CASE_INSENSITIVE)
                .matcher(value).replaceAll("$1[REDACTED]@");
        return Pattern.compile("([?&](?:access_token|api[_-]?key|auth|code|credential|key|password|secret|session|sig|signature|token|x-amz-signature)=)[^&#\\s]+",
                        Pattern.CASE_INSENSITIVE)
                .matcher(redacted).replaceAll("$1[REDACTED]");
    }

    public void redactPreview(List<String> sensitiveValues) {
        String output = preview
                .replaceAll("(?im)^(Authorization|Cookie|Set-Cookie|Proxy-Authorization):.*$", "$1: [REDACTED]");
        output = redactUrlValue(output);
        if (sensitiveValues != null) {
            for (String secret : sensitiveValues) {
                if (secret != null && !secret.isEmpty()) output = output.replace(secret, mask(secret));
            }
        }
        preview = output;
    }

    private static boolean defaultSensitiveValue(FindingKind kind) {
        return kind != FindingKind.ENDPOINT && kind != FindingKind.CONFIGURATION && kind != FindingKind.VULNERABILITY;
    }

    private static String mask(String value) {
        if (value.length() <= 8) return "[REDACTED]";
        return value.substring(0, Math.min(4, value.length())) + "…" + value.substring(value.length() - 4);
    }

    public String valueFingerprint() { return sha256(rawValue); }
    public String fingerprint() { return fingerprint; }
    public Instant discoveredAt() { return discoveredAt; }
    public String ruleId() { return ruleId; }
    public String ruleName() { return ruleName; }
    public FindingKind kind() { return kind; }
    public Severity severity() { return severity; }
    public Confidence confidence() { return confidence; }
    public String assetUrl() { return assetUrl; }
    public String rootUrl() { return rootUrl; }
    public List<String> discoveryChain() { return discoveryChain; }
    public int line() { return line; }
    public int start() { return start; }
    public int end() { return end; }
    public String preview() { return preview; }
    public String rawValue() { return rawValue; }
    public boolean sensitiveValue() { return sensitiveValue; }
    public String description() { return description; }
    public String remediation() { return remediation; }
    public HttpRequest request() { return request; }
    public HttpResponse response() { return response; }
    public ReviewStatus reviewStatus() { return reviewStatus; }
    public void reviewStatus(ReviewStatus value) { reviewStatus = Objects.requireNonNull(value); }
    public boolean published() { return published; }
    public void published(boolean value) { published = value; }
}
