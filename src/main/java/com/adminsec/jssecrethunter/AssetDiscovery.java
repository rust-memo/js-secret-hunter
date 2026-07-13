package com.adminsec.jssecrethunter;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AssetDiscovery {
    private static final Pattern IMPORT = Pattern.compile("(?is)(?:import\\s*(?:[^'\\\"]*?\\sfrom\\s*)?|import\\s*\\(|require\\s*\\()\\s*['\\\"]([^'\\\"]+)['\\\"]");
    private static final Pattern SOURCE_MAP = Pattern.compile("(?im)[#@]\\s*sourceMappingURL\\s*=\\s*([^\\s*]+)");
    private static final Pattern JS_URL = Pattern.compile("(?i)(?:https?:)?//[^\\s'\\\"<>]+?\\.(?:m?js|cjs)(?:\\?[^\\s'\\\"<>]*)?|(?:[./][^\\s'\\\"<>]*?\\.(?:m?js|cjs)(?:\\?[^\\s'\\\"<>]*)?)");
    private static final Pattern MAP_URL = Pattern.compile("(?i)(?:https?:)?//[^\\s'\\\"<>]+?\\.map(?:\\?[^\\s'\\\"<>]*)?|(?:[./][^\\s'\\\"<>]*?\\.map(?:\\?[^\\s'\\\"<>]*)?)");

    public Set<String> discover(String baseUrl, String body, boolean html, boolean javascript) {
        Set<String> raw = new LinkedHashSet<>();
        if (body == null || body.isBlank()) return raw;
        if (html) {
            Document document = Jsoup.parse(body, baseUrl);
            for (Element script : document.select("script[src]")) add(raw, script.absUrl("src"), script.attr("src"));
            for (Element link : document.select("link[href]")) {
                String rel = link.attr("rel").toLowerCase(Locale.ROOT);
                String as = link.attr("as").toLowerCase(Locale.ROOT);
                if (rel.contains("modulepreload") || (rel.contains("preload") && as.equals("script"))) {
                    add(raw, link.absUrl("href"), link.attr("href"));
                }
            }
        }
        if (javascript) {
            collect(IMPORT, body, 1, raw);
            collect(SOURCE_MAP, body, 1, raw);
            collect(MAP_URL, body, 0, raw);
        }
        collect(JS_URL, body, 0, raw);

        Set<String> resolved = new LinkedHashSet<>();
        for (String candidate : raw) {
            String normalized = resolve(baseUrl, clean(candidate));
            if (normalized != null) resolved.add(normalized);
        }
        return resolved;
    }

    public static boolean isJavaScriptUrl(String url) {
        String path = path(url);
        return path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs");
    }

    public static boolean isSourceMapUrl(String url) { return path(url).endsWith(".map"); }

    private static String path(String url) {
        try { return new URI(url).getPath().toLowerCase(Locale.ROOT); }
        catch (Exception ignored) { return url.toLowerCase(Locale.ROOT).split("[?#]", 2)[0]; }
    }

    private static void collect(Pattern pattern, String text, int group, Set<String> out) {
        Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find() && count++ < 2_000) add(out, null, matcher.group(group));
    }

    private static void add(Set<String> out, String absolute, String fallback) {
        String value = absolute != null && !absolute.isBlank() ? absolute : fallback;
        if (value != null && !value.isBlank()) out.add(value);
    }

    private static String clean(String value) {
        return value.trim().replace("\\/", "/").replaceAll("[),;]+$", "");
    }

    static String resolve(String base, String candidate) {
        String lower = candidate.toLowerCase(Locale.ROOT);
        if (lower.startsWith("data:") || lower.startsWith("blob:") || lower.startsWith("javascript:") || lower.startsWith("webpack:")) return null;
        try {
            URI baseUri = new URI(base);
            URI value = candidate.startsWith("//") ? new URI(baseUri.getScheme() + ":" + candidate) : baseUri.resolve(candidate);
            if (!Set.of("http", "https").contains(value.getScheme() == null ? "" : value.getScheme().toLowerCase(Locale.ROOT))) return null;
            if (value.getRawUserInfo() != null) return null;
            return new URI(value.getScheme().toLowerCase(Locale.ROOT), value.getUserInfo(), value.getHost() == null ? null : value.getHost().toLowerCase(Locale.ROOT),
                    value.getPort(), value.getPath(), value.getQuery(), null).toASCIIString();
        } catch (URISyntaxException | IllegalArgumentException invalid) { return null; }
    }
}
