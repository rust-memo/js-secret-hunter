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
    private final String preview;
    private final String rawValue;
    private final HttpRequest request;
    private final HttpResponse response;
    private volatile ReviewStatus reviewStatus = ReviewStatus.NEEDS_REVIEW;

    public Finding(String ruleId, String ruleName, FindingKind kind, Severity severity, Confidence confidence,
                   String assetUrl, String rootUrl, List<String> discoveryChain, int line, int start, int end,
                   String preview, String rawValue, HttpRequest request, HttpResponse response) {
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
        if (kind == FindingKind.ENDPOINT || kind == FindingKind.CONFIGURATION) return rawValue;
        if (rawValue.length() <= 8) return "••••••••";
        return rawValue.substring(0, Math.min(4, rawValue.length())) + "…" + rawValue.substring(rawValue.length() - 4);
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
    public HttpRequest request() { return request; }
    public HttpResponse response() { return response; }
    public ReviewStatus reviewStatus() { return reviewStatus; }
    public void reviewStatus(ReviewStatus value) { reviewStatus = Objects.requireNonNull(value); }
}
