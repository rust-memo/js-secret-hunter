package com.adminsec.jssecrethunter;

import com.adminsec.jssecrethunter.model.RuleDefinition;
import com.adminsec.jssecrethunter.model.RulePackDocument;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.Strictness;
import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class RulePackManager {
    private static final int MAX_RULES = 2_000;
    private static final int MAX_REGEX_LENGTH = 10_000;
    private final Gson gson = new GsonBuilder().setStrictness(Strictness.STRICT).disableHtmlEscaping().create();
    private final LoadedRulePack bundled;
    private volatile LoadedRulePack current;

    public RulePackManager() {
        try (InputStream in = RulePackManager.class.getResourceAsStream("/default-rules.json")) {
            if (in == null) throw new IllegalStateException("Bundled rule pack is missing");
            bundled = parse(in.readAllBytes());
            current = bundled;
        } catch (IOException error) {
            throw new IllegalStateException("Cannot read bundled rule pack", error);
        }
    }

    public LoadedRulePack current() { return current; }
    public LoadedRulePack bundled() { return bundled; }

    public synchronized LoadedRulePack validate(byte[] json) { return parse(json); }
    public synchronized void apply(LoadedRulePack pack) { current = pack; }
    public synchronized void restoreBundled() { current = bundled; }

    private LoadedRulePack parse(byte[] json) {
        if (json == null || json.length == 0 || json.length > 5 * 1024 * 1024) {
            throw new IllegalArgumentException("Rule pack must be between 1 byte and 5 MB");
        }
        RulePackDocument document;
        try { document = gson.fromJson(new String(json, StandardCharsets.UTF_8), RulePackDocument.class); }
        catch (RuntimeException error) { throw new IllegalArgumentException("Invalid rule-pack JSON", error); }
        if (document == null || document.schemaVersion != 1) throw new IllegalArgumentException("Unsupported rule-pack schema");
        if (document.version == null || document.version.isBlank()) throw new IllegalArgumentException("Rule-pack version is required");
        if (document.rules == null || document.rules.isEmpty() || document.rules.size() > MAX_RULES) {
            throw new IllegalArgumentException("Rule pack must contain 1-" + MAX_RULES + " rules");
        }
        Set<String> ids = new HashSet<>();
        List<CompiledRule> compiled = new ArrayList<>();
        for (RuleDefinition rule : document.rules) {
            validateRule(rule, ids);
            if (!rule.enabled) continue;
            try {
                Pattern regex = Pattern.compile(rule.regex);
                if (rule.secretGroup > regex.matcher("").groupCount()) {
                    throw new IllegalArgumentException("secretGroup exceeds capture groups in rule " + rule.id);
                }
                Pattern allowlist = rule.allowlistRegex == null || rule.allowlistRegex.isBlank()
                        ? null : Pattern.compile(rule.allowlistRegex);
                List<String> keywords = rule.keywords == null ? List.of() : rule.keywords.stream()
                        .filter(v -> v != null && !v.isBlank()).map(v -> v.toLowerCase(Locale.ROOT)).toList();
                compiled.add(new CompiledRule(rule, regex, allowlist, keywords));
            } catch (PatternSyntaxException error) {
                throw new IllegalArgumentException("Invalid RE2 expression in rule " + rule.id + ": " + error.getMessage(), error);
            }
        }
        if (compiled.isEmpty()) throw new IllegalArgumentException("Rule pack has no enabled rules");
        return new LoadedRulePack(document.version, document.releasedAt == null ? "" : document.releasedAt,
                sha256(json), List.copyOf(compiled), json.clone());
    }

    private static void validateRule(RuleDefinition r, Set<String> ids) {
        if (r == null || r.id == null || !r.id.matches("[a-z0-9][a-z0-9._-]{1,79}")) {
            throw new IllegalArgumentException("Every rule needs a stable lowercase id");
        }
        if (!ids.add(r.id)) throw new IllegalArgumentException("Duplicate rule id: " + r.id);
        if (r.name == null || r.name.isBlank() || r.kind == null || r.severity == null || r.confidence == null) {
            throw new IllegalArgumentException("Incomplete rule: " + r.id);
        }
        if (r.regex == null || r.regex.isBlank() || r.regex.length() > MAX_REGEX_LENGTH) {
            throw new IllegalArgumentException("Invalid regex length in rule: " + r.id);
        }
        if (r.secretGroup < 0 || r.secretGroup > 20 || r.minLength < 0 || r.minLength > 10_000
                || r.minEntropy < 0 || r.minEntropy > 8) {
            throw new IllegalArgumentException("Invalid thresholds in rule: " + r.id);
        }
    }

    private static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    public record CompiledRule(RuleDefinition definition, Pattern regex, Pattern allowlist, List<String> keywords) {}
    public record LoadedRulePack(String version, String releasedAt, String sha256,
                                 List<CompiledRule> rules, byte[] source) {
        public String shortHash() { return sha256.substring(0, Math.min(12, sha256.length())); }
    }
}
