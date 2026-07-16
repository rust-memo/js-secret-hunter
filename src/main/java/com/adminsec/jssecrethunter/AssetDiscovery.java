package com.adminsec.jssecrethunter;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AssetDiscovery {
    private static final Pattern IMPORT = Pattern.compile("(?is)(?:(?:import|export)\\s+(?:[^'\\\"]*?\\sfrom\\s*)?|import\\s*\\(|require\\s*\\()\\s*['\\\"]([^'\\\"]+)['\\\"]");
    private static final Pattern WORKER = Pattern.compile("(?is)(?:new\\s+(?:Shared)?Worker\\s*\\(|serviceWorker\\s*\\.\\s*register\\s*\\()\\s*['\\\"]([^'\\\"]+)['\\\"]");
    private static final Pattern SOURCE_MAP = Pattern.compile("(?im)[#@]\\s*sourceMappingURL\\s*=\\s*([^\\s*]+)");
    private static final Pattern JS_URL = Pattern.compile("(?i)(?:https?:)?//[^\\s'\\\"<>]+?\\.(?:m?js|cjs)(?:\\?[^\\s'\\\"<>]*)?|(?:[./][^\\s'\\\"<>]*?\\.(?:m?js|cjs)(?:\\?[^\\s'\\\"<>]*)?)");
    private static final Pattern MAP_URL = Pattern.compile("(?i)(?:https?:)?//[^\\s'\\\"<>]+?\\.map(?:\\?[^\\s'\\\"<>]*)?|(?:[./][^\\s'\\\"<>]*?\\.map(?:\\?[^\\s'\\\"<>]*)?)");

    public Set<String> discover(String baseUrl, String body, boolean html, boolean javascript) {
        Set<String> urls = new LinkedHashSet<>();
        for (DiscoveredAsset asset : discoverAssets(baseUrl, body, html, javascript)) urls.add(asset.url());
        return urls;
    }

    public Set<DiscoveredAsset> discoverAssets(String baseUrl, String body, boolean html, boolean javascript) {
        Map<String, RawAsset> raw = new LinkedHashMap<>();
        if (body == null || body.isBlank()) return Set.of();
        if (html) {
            Document document = Jsoup.parse(body, baseUrl);
            for (Element script : document.select("script[src]")) {
                add(raw, script.absUrl("src"), script.attr("src"), ContentClass.JAVASCRIPT, "script[src]");
            }
            for (Element script : document.select("script:not([src])")) {
                collectResolved(IMPORT, script.data(), 1, script.baseUri(), raw, "inline script import");
                collectResolved(WORKER, script.data(), 1, script.baseUri(), raw, "inline worker");
            }
            for (Element link : document.select("link[href]")) {
                String rel = link.attr("rel").toLowerCase(Locale.ROOT);
                String as = link.attr("as").toLowerCase(Locale.ROOT);
                if (rel.contains("modulepreload") || (rel.contains("preload") && as.equals("script"))) {
                    add(raw, link.absUrl("href"), link.attr("href"), ContentClass.JAVASCRIPT, "script preload");
                }
            }
        }
        if (javascript) {
            collect(IMPORT, body, 1, raw, ContentClass.JAVASCRIPT, "static import");
            collect(WORKER, body, 1, raw, ContentClass.JAVASCRIPT, "worker script");
            collect(SOURCE_MAP, body, 1, raw, ContentClass.SOURCE_MAP, "sourceMappingURL");
            collect(MAP_URL, body, 0, raw, ContentClass.SOURCE_MAP, "source map URL");
        }
        collect(JS_URL, body, 0, raw, ContentClass.JAVASCRIPT, "JavaScript URL");

        Map<String, DiscoveredAsset> resolved = new LinkedHashMap<>();
        for (RawAsset candidate : raw.values()) {
            String normalized = resolve(baseUrl, clean(candidate.value));
            if (normalized != null) {
                resolved.putIfAbsent(normalized, new DiscoveredAsset(normalized, candidate.contentClass, candidate.source));
            }
        }
        return new LinkedHashSet<>(resolved.values());
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

    private static void collect(Pattern pattern, String text, int group, Map<String, RawAsset> out,
                                ContentClass contentClass, String source) {
        Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find() && count++ < 2_000) {
            String value = matcher.group(group);
            if ("static import".equals(source) && !isResolvableImport(value)) continue;
            add(out, null, value, contentClass, source);
        }
    }

    private static void collectResolved(Pattern pattern, String text, int group, String base,
                                        Map<String, RawAsset> out, String source) {
        if (text == null || text.isBlank()) return;
        Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find() && count++ < 2_000) {
            String value = matcher.group(group);
            if ("inline script import".equals(source) && !isResolvableImport(value)) continue;
            String resolved = resolve(base, clean(value));
            if (resolved != null) add(out, resolved, value, ContentClass.JAVASCRIPT, source);
        }
    }

    private static boolean isResolvableImport(String value) {
        if (value == null) return false;
        String candidate = value.trim().toLowerCase(Locale.ROOT);
        return candidate.startsWith("./") || candidate.startsWith("../") || candidate.startsWith("/")
                || candidate.startsWith("//") || candidate.startsWith("http://") || candidate.startsWith("https://");
    }

    private static void add(Map<String, RawAsset> out, String absolute, String fallback,
                            ContentClass contentClass, String source) {
        String value = absolute != null && !absolute.isBlank() ? absolute : fallback;
        if (value != null && !value.isBlank()) out.putIfAbsent(value, new RawAsset(value, contentClass, source));
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

    private record RawAsset(String value, ContentClass contentClass, String source) {}
}
