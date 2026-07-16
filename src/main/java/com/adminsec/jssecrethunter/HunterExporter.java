package com.adminsec.jssecrethunter;

import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class HunterExporter {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private HunterExporter() {}

    public static String json(List<Finding> findings, boolean includeRaw) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Finding f : findings) rows.add(row(f, includeRaw));
        return GSON.toJson(rows) + "\n";
    }

    public static String csv(List<Finding> findings, boolean includeRaw) {
        StringBuilder out = new StringBuilder("severity,confidence,kind,rule,asset_url,resolved_url,root_url,line,value,value_sha256,status,description,remediation\n");
        for (Finding f : findings) {
            String value = includeRaw ? f.rawValue() : f.maskedValue();
            out.append(csv(f.severity().name())).append(',').append(csv(f.confidence().name())).append(',')
                    .append(csv(f.kind().name())).append(',').append(csv(f.ruleName())).append(',')
                    .append(csv(presentUrl(f.assetUrl(), includeRaw))).append(',').append(csv(resolvedUrl(f, includeRaw))).append(',')
                    .append(csv(presentUrl(f.rootUrl(), includeRaw))).append(',').append(f.line()).append(',')
                    .append(csv(value)).append(',').append(csv(f.valueFingerprint())).append(',')
                    .append(csv(f.reviewStatus().name())).append(',').append(csv(f.description())).append(',')
                    .append(csv(f.remediation())).append('\n');
        }
        return out.toString();
    }

    private static Map<String, Object> row(Finding f, boolean includeRaw) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("severity", f.severity()); row.put("confidence", f.confidence()); row.put("kind", f.kind());
        row.put("ruleId", f.ruleId()); row.put("ruleName", f.ruleName()); row.put("assetUrl", presentUrl(f.assetUrl(), includeRaw));
        row.put("resolvedUrl", resolvedUrl(f, includeRaw));
        row.put("rootUrl", presentUrl(f.rootUrl(), includeRaw));
        row.put("discoveryChain", f.discoveryChain().stream().map(url -> presentUrl(url, includeRaw)).toList()); row.put("line", f.line());
        row.put("value", includeRaw ? f.rawValue() : f.maskedValue()); row.put("valueSha256", f.valueFingerprint());
        row.put("preview", f.preview()); row.put("status", f.reviewStatus());
        row.put("description", f.description()); row.put("remediation", f.remediation());
        return row;
    }

    static String resolvedUrl(Finding finding) {
        if (finding.kind() != FindingKind.ENDPOINT || finding.rawValue().isBlank()) return "";
        String raw = finding.rawValue().trim();
        String lower = raw.toLowerCase(Locale.ROOT);
        if (lower.startsWith("ws://") || lower.startsWith("wss://")) return raw;
        String resolved = AssetDiscovery.resolve(finding.assetUrl(), raw);
        return resolved == null ? raw : resolved;
    }

    static String resolvedUrl(Finding finding, boolean includeRaw) {
        String resolved = resolvedUrl(finding);
        return includeRaw ? resolved : Finding.redactUrlValue(resolved);
    }

    private static String presentUrl(String value, boolean includeRaw) {
        return includeRaw ? value : Finding.redactUrlValue(value);
    }

    private static String csv(String value) {
        String safe = value == null ? "" : value;
        String trimmed = safe.stripLeading();
        if (!trimmed.isEmpty() && "=+-@".indexOf(trimmed.charAt(0)) >= 0) safe = "'" + safe;
        return "\"" + safe.replace("\"", "\"\"") + "\"";
    }
}
