package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.adminsec.jssecrethunter.RulePackManager.CompiledRule;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.google.re2j.Matcher;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class DetectionEngine {
    private static final int MAX_MATCHES_PER_RULE = 100;
    private static final int MAX_DECODED_VIEWS = 500;
    private static final Pattern QUOTED = Pattern.compile("(['\\\"])(.{8,4096}?)\\1", Pattern.DOTALL);
    private static final Pattern BASE64 = Pattern.compile("(?<![A-Za-z0-9+/_=-])([A-Za-z0-9+/_-]{20,4092}={0,2})(?![A-Za-z0-9+/_=-])");
    private final RulePackManager rules;

    public DetectionEngine(RulePackManager rules) { this.rules = rules; }

    public List<Finding> scan(String text, String assetUrl, String rootUrl, List<String> chain,
                              HttpRequest request, HttpResponse response) {
        if (text == null || text.isBlank()) return List.of();
        List<ContentView> views = decodedViews(text);
        Map<String, Finding> out = new LinkedHashMap<>();
        for (CompiledRule rule : rules.current().rules()) {
            for (ContentView view : views) scanRule(rule, view, assetUrl, rootUrl, chain, request, response, out);
        }
        List<Finding> findings = new ArrayList<>(out.values());
        List<String> sensitiveValues = findings.stream()
                .filter(Finding::sensitiveValue)
                .map(Finding::rawValue)
                .filter(value -> !value.isEmpty())
                .distinct()
                .sorted(Comparator.comparingInt(String::length).reversed())
                .toList();
        findings.forEach(finding -> finding.redactPreview(sensitiveValues));
        findings.sort(Comparator.comparingInt((Finding finding) -> finding.severity().rank())
                .thenComparingInt(finding -> finding.kind() == FindingKind.ENDPOINT ? 1 : 0)
                .thenComparingInt(finding -> finding.confidence().ordinal()));
        return findings;
    }

    private void scanRule(CompiledRule rule, ContentView view, String assetUrl, String rootUrl, List<String> chain,
                          HttpRequest request, HttpResponse response, Map<String, Finding> out) {
        String lower = view.text.toLowerCase(Locale.ROOT);
        if (!rule.keywords().isEmpty() && rule.keywords().stream().noneMatch(lower::contains)) return;
        Matcher matcher = rule.regex().matcher(view.text);
        int count = 0;
        while (matcher.find() && count++ < MAX_MATCHES_PER_RULE) {
            int group = rule.definition().secretGroup;
            String raw;
            String value;
            int localStart;
            int localEnd;
            try {
                raw = matcher.group(group);
                if (raw == null) continue;
                value = raw.trim();
                int leadingWhitespace = raw.length() - raw.stripLeading().length();
                localStart = matcher.start(group) + leadingWhitespace;
                localEnd = localStart + value.length();
            } catch (RuntimeException invalidGroup) { continue; }
            if (value.length() < rule.definition().minLength) continue;
            if (rule.allowlist() != null && rule.allowlist().matcher(value).find()) continue;
            if (rule.definition().minEntropy > 0 && shannonEntropy(value) < rule.definition().minEntropy) continue;
            int start = Math.max(0, view.sourceOffset + localStart);
            int end = Math.max(start, view.sourceOffset + localEnd);
            int line = view.sourceLine + lineAt(view.text, Math.min(localStart, view.text.length())) - 1;
            String preview = view.label + " | " + snippet(view.text, localStart, localEnd, value);
            Finding finding = new Finding(rule.definition().id, rule.definition().name, rule.definition().kind,
                    rule.definition().severity, rule.definition().confidence, assetUrl, rootUrl, chain,
                    line, start, end, preview, value, sensitiveValue(rule.definition()),
                    rule.definition().description, rule.definition().remediation, request, response);
            String key = rule.definition().kind == FindingKind.ENDPOINT
                    ? "endpoint\n" + value + "\n" + start
                    : rule.definition().id + "\n" + value + "\n" + start;
            out.putIfAbsent(key, finding);
        }
    }

    private static List<ContentView> decodedViews(String text) {
        List<ContentView> views = new ArrayList<>();
        views.add(new ContentView(text, 0, 1, "source"));
        Set<String> seen = new HashSet<>();
        String decodedSource = decodeEscapes(text);
        if (!decodedSource.equals(text) && seen.add(decodedSource)) {
            views.add(new ContentView(decodedSource, 0, 1, "decoded-source"));
        }
        java.util.regex.Matcher quoted = QUOTED.matcher(text);
        while (quoted.find() && views.size() < MAX_DECODED_VIEWS) {
            String raw = quoted.group(2);
            String decoded = decodeEscapes(raw);
            if (!decoded.equals(raw) && seen.add(decoded)) {
                views.add(new ContentView(decoded, quoted.start(2), lineAt(text, quoted.start(2)), "decoded-js-string"));
            }
        }
        java.util.regex.Matcher base64 = BASE64.matcher(text);
        while (base64.find() && views.size() < MAX_DECODED_VIEWS) {
            String candidate = base64.group(1);
            try {
                Base64.Decoder decoder = candidate.indexOf('-') >= 0 || candidate.indexOf('_') >= 0
                        ? Base64.getUrlDecoder() : Base64.getDecoder();
                byte[] bytes = decoder.decode(candidate);
                if (bytes.length < 8 || bytes.length > 64 * 1024) continue;
                String decoded = new String(bytes, StandardCharsets.UTF_8);
                if (printableRatio(decoded) >= .85 && seen.add(decoded)) {
                    views.add(new ContentView(decoded, base64.start(1), lineAt(text, base64.start(1)), "decoded-base64"));
                }
            } catch (IllegalArgumentException ignored) { }
        }
        return views;
    }

    static String decodeEscapes(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) { out.append(c); continue; }
            char n = value.charAt(++i);
            switch (n) {
                case 'n' -> out.append('\n'); case 'r' -> out.append('\r'); case 't' -> out.append('\t');
                case '\\' -> out.append('\\'); case '/' -> out.append('/'); case '\'' -> out.append('\''); case '"' -> out.append('"');
                case 'x' -> { if (i + 2 < value.length()) { appendHex(out, value, i + 1, 2); i += 2; } else out.append(n); }
                case 'u' -> { if (i + 4 < value.length()) { appendHex(out, value, i + 1, 4); i += 4; } else out.append(n); }
                default -> out.append(n);
            }
        }
        return out.toString();
    }

    private static void appendHex(StringBuilder out, String value, int start, int length) {
        try { out.append((char) Integer.parseInt(value.substring(start, start + length), 16)); }
        catch (NumberFormatException error) { out.append(value, Math.max(0, start - 2), Math.min(value.length(), start + length)); }
    }

    static double shannonEntropy(String value) {
        if (value == null || value.isEmpty()) return 0;
        Map<Integer, Integer> counts = new java.util.HashMap<>();
        value.codePoints().forEach(cp -> counts.merge(cp, 1, Integer::sum));
        double entropy = 0;
        for (int count : counts.values()) {
            double p = (double) count / value.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private static double printableRatio(String value) {
        if (value.isEmpty()) return 0;
        return (double) value.chars().filter(c -> c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127)).count() / value.length();
    }

    private static int lineAt(String text, int offset) {
        int line = 1;
        for (int i = 0; i < Math.min(offset, text.length()); i++) if (text.charAt(i) == '\n') line++;
        return line;
    }

    private static boolean sensitiveValue(com.adminsec.jssecrethunter.model.RuleDefinition definition) {
        return definition.sensitiveValue || (definition.kind != FindingKind.ENDPOINT
                && definition.kind != FindingKind.CONFIGURATION && definition.kind != FindingKind.VULNERABILITY);
    }

    private static String snippet(String text, int start, int end, String value) {
        int from = Math.max(0, start - 100), to = Math.min(text.length(), end + 120);
        String context = text.substring(from, to).replaceAll("\\s+", " ");
        if (!value.isBlank()) context = context.replace(value, mask(value));
        return context.length() <= 500 ? context : context.substring(0, 500) + "…";
    }

    private static String mask(String value) {
        if (value.length() <= 8) return "[REDACTED]";
        return value.substring(0, 4) + "…" + value.substring(value.length() - 4);
    }

    private record ContentView(String text, int sourceOffset, int sourceLine, String label) {}
}
