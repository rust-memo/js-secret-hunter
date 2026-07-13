package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.adminsec.jssecrethunter.model.AssetRecord;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.Severity;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class ScannerService {
    private static final String NOTE = "[JS Secret Hunter]";
    private static final Set<String> CREDENTIAL_HEADERS = Set.of("cookie", "authorization");
    private static final Set<String> CONTEXT_HEADERS = Set.of("user-agent", "accept-language");
    private final MontoyaApi api;
    private final HunterConfig config;
    private final HunterRepository repository;
    private final DetectionEngine detector;
    private final AssetDiscovery discovery = new AssetDiscovery();
    private final ThreadPoolExecutor workers;
    private final ExecutorService coordinator;
    private final ScheduledThreadPoolExecutor scheduler;
    private final Map<String, ProxyHttpRequestResponse> historyIndex = new ConcurrentHashMap<>();
    private final Map<String, Observed> observedCache = new ConcurrentHashMap<>();
    private final Map<String, Semaphore> hostLimits = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> rootCounts = new ConcurrentHashMap<>();
    private final Map<String, Annotations> rootAnnotations = new ConcurrentHashMap<>();
    private final Set<String> scheduled = ConcurrentHashMap.newKeySet();
    private final Set<String> processed = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final AtomicBoolean historyScanning = new AtomicBoolean(false);
    private final AtomicLong epoch = new AtomicLong();

    public ScannerService(MontoyaApi api, HunterConfig config, HunterRepository repository, DetectionEngine detector) {
        this.api = api; this.config = config; this.repository = repository; this.detector = detector;
        workers = (ThreadPoolExecutor) Executors.newFixedThreadPool(config.workers(), r -> daemon(r, "js-secret-hunter-worker"));
        coordinator = Executors.newSingleThreadExecutor(r -> daemon(r, "js-secret-hunter-history"));
        scheduler = new ScheduledThreadPoolExecutor(1, r -> daemon(r, "js-secret-hunter-delay"));
        scheduler.setRemoveOnCancelPolicy(true);
    }

    public void scanHistory() {
        if (!historyScanning.compareAndSet(false, true)) {
            api.logging().logToOutput("JS Secret Hunter: history scan is already running."); return;
        }
        coordinator.submit(() -> {
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history(item -> item.finalRequest() != null);
                for (ProxyHttpRequestResponse item : history) historyIndex.put(canonical(item.finalRequest().url()), item);
                for (ProxyHttpRequestResponse item : history) {
                    if (stopping.get()) return;
                    waitIfPaused();
                    if (item.hasResponse()) observe(item.finalRequest(), item.response(), item.annotations());
                }
                api.logging().logToOutput("JS Secret Hunter: queued history scan for " + history.size() + " entries.");
            } catch (RuntimeException error) { api.logging().logToError("JS Secret Hunter history scan failed", error); }
            finally { historyScanning.set(false); }
        });
    }

    public void observe(HttpRequest request, HttpResponse response, Annotations annotations) {
        if (request == null || response == null || stopping.get()) return;
        String url = canonical(request.url());
        observedCache.put(url, new Observed(request, response));
        rootAnnotations.putIfAbsent(url, annotations);
        workers.submit(() -> process(new Work(url, url, url, 0, List.of(url), request, response, true, epoch.get())));
    }

    private void process(Work work) {
        if (stopping.get() || work.epoch != epoch.get()) return;
        waitIfPaused();
        String processKey = work.rootUrl + "\n" + canonical(work.url) + "\n" + work.response.statusCode() + "\n" + work.response.body().length();
        if (!processed.add(processKey)) return;
        int limit = AssetDiscovery.isSourceMapUrl(work.url) ? config.maxMapBytes() : config.maxJsBytes();
        boolean script = isJavaScript(work.request, work.response, work.url);
        boolean map = AssetDiscovery.isSourceMapUrl(work.url);
        boolean html = isHtml(work.response, work.url);
        boolean textual = script || map || html || isTextual(work.response);
        if (!textual) {
            repository.upsertAsset(asset(work, AssetRecord.AssetStatus.SKIPPED, "Non-text response")); return;
        }
        String body = TextBody.decode(work.response, limit);
        if (body == null) {
            repository.upsertAsset(asset(work, AssetRecord.AssetStatus.SKIPPED, "Unsupported encoding or size limit")); return;
        }
        List<Finding> findings = (script || map || html)
                ? detector.scan(body, work.url, work.rootUrl, work.chain, work.request, work.response) : List.of();
        repository.addFindings(findings);
        repository.upsertAsset(asset(work, AssetRecord.AssetStatus.SCANNED,
                findings.size() + " findings; " + body.length() + " chars"));
        annotate(work.rootUrl, findings);

        if (work.depth >= config.maxDepth()) return;
        Set<String> links = discovery.discover(work.url, body, html, script || map);
        for (String link : links) scheduleLink(work, link);
    }

    private void scheduleLink(Work parent, String link) {
        if (!AssetDiscovery.isJavaScriptUrl(link) && !AssetDiscovery.isSourceMapUrl(link)) return;
        AtomicInteger count = rootCounts.computeIfAbsent(parent.rootUrl, ignored -> new AtomicInteger());
        if (count.incrementAndGet() > config.maxAssetsPerRoot()) return;
        List<String> chain = new ArrayList<>(parent.chain); chain.add(link);
        ProxyHttpRequestResponse existing = historyIndex.get(canonical(link));
        if (existing != null && existing.hasResponse()) {
            process(new Work(link, parent.url, parent.rootUrl, parent.depth + 1, chain,
                    existing.finalRequest(), existing.response(), false, parent.epoch));
            return;
        }
        Observed observed = observedCache.get(canonical(link));
        if (observed != null) {
            process(new Work(link, parent.url, parent.rootUrl, parent.depth + 1, chain,
                    observed.request, observed.response, false, parent.epoch));
            return;
        }
        if (!config.autoFetch()) return;
        HttpRequest scopeProbe;
        try { scopeProbe = HttpRequest.httpRequestFromUrl(link); }
        catch (RuntimeException invalid) { return; }
        if (!scopeProbe.isInScope()) {
            repository.upsertAsset(new AssetRecord(link, parent.url, parent.rootUrl, parent.depth + 1, chain,
                    AssetRecord.AssetStatus.SKIPPED, "Outside Target Scope", scopeProbe, null, Instant.now()));
            return;
        }
        String key = canonical(link);
        if (!scheduled.add(key)) return;
        repository.upsertAsset(new AssetRecord(link, parent.url, parent.rootUrl, parent.depth + 1, chain,
                AssetRecord.AssetStatus.QUEUED, "Waiting for background fetch", scopeProbe, null, Instant.now()));
        scheduler.schedule(() -> {
            if (parent.epoch != epoch.get()) return;
            Observed late = observedCache.get(canonical(link));
            if (late != null) {
                workers.submit(() -> process(new Work(link, parent.url, parent.rootUrl, parent.depth + 1, chain,
                        late.request, late.response, false, parent.epoch)));
            } else {
                workers.submit(() -> fetch(link, parent, chain, 0));
            }
        }, 500, TimeUnit.MILLISECONDS);
    }

    private void fetch(String url, Work parent, List<String> chain, int redirects) {
        waitIfPaused();
        if (stopping.get() || parent.epoch != epoch.get()) return;
        HttpRequest request = requestFor(url, parent.request);
        if (!request.isInScope()) return;
        Semaphore limit = hostLimits.computeIfAbsent(host(url), ignored -> new Semaphore(config.perHost()));
        boolean acquired = false;
        try {
            limit.acquire(); acquired = true;
            repository.upsertAsset(new AssetRecord(url, parent.url, parent.rootUrl, parent.depth + 1, chain,
                    AssetRecord.AssetStatus.FETCHING, "GET in progress", request, null, Instant.now()));
            HttpRequestResponse rr = api.http().sendRequest(request, RequestOptions.requestOptions()
                    .withRedirectionMode(RedirectionMode.NEVER).withResponseTimeout(config.timeoutSeconds() * 1000L));
            if (parent.epoch != epoch.get()) return;
            if (rr == null || !rr.hasResponse()) {
                repository.upsertAsset(new AssetRecord(url, parent.url, parent.rootUrl, parent.depth + 1, chain,
                        AssetRecord.AssetStatus.FAILED, "No response", request, null, Instant.now())); return;
            }
            HttpResponse response = rr.response();
            if (response.statusCode() >= 300 && response.statusCode() < 400 && response.hasHeader("Location") && redirects < 3) {
                String target = AssetDiscovery.resolve(url, response.headerValue("Location"));
                if (target != null) {
                    HttpRequest probe = HttpRequest.httpRequestFromUrl(target);
                    if (probe.isInScope()) {
                        List<String> redirected = new ArrayList<>(chain); redirected.add(target);
                        limit.release(); acquired = false;
                        fetch(target, new Work(url, parent.url, parent.rootUrl, parent.depth, chain, request, response, false, parent.epoch), redirected, redirects + 1);
                        return;
                    }
                }
            }
            observedCache.put(canonical(url), new Observed(request, response));
            process(new Work(url, parent.url, parent.rootUrl, parent.depth + 1, chain, request, response, false, parent.epoch));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException error) {
            repository.upsertAsset(new AssetRecord(url, parent.url, parent.rootUrl, parent.depth + 1, chain,
                    AssetRecord.AssetStatus.FAILED, safeMessage(error), request, null, Instant.now()));
            api.logging().logToError("JS asset fetch failed for " + url + ": " + safeMessage(error));
        } finally { if (acquired) limit.release(); }
    }

    static HttpRequest requestFor(String url, HttpRequest parent) {
        HttpRequest target = HttpRequest.httpRequestFromUrl(url);
        boolean sameOrigin = sameOrigin(url, parent.url());
        for (var header : parent.headers()) {
            String name = header.name().toLowerCase(Locale.ROOT);
            if (CONTEXT_HEADERS.contains(name) || (sameOrigin && CREDENTIAL_HEADERS.contains(name))) {
                target = target.withUpdatedHeader(header.name(), header.value());
            }
        }
        return target.withUpdatedHeader("Accept", "application/javascript, text/javascript, application/json, */*;q=0.8");
    }

    static boolean sameOrigin(String left, String right) {
        try {
            URI a = URI.create(left), b = URI.create(right);
            return a.getScheme().equalsIgnoreCase(b.getScheme()) && a.getHost().equalsIgnoreCase(b.getHost())
                    && effectivePort(a) == effectivePort(b);
        } catch (RuntimeException error) { return false; }
    }

    private void annotate(String rootUrl, List<Finding> findings) {
        if (findings.isEmpty()) return;
        Annotations annotations = rootAnnotations.get(rootUrl);
        if (annotations == null) return;
        Severity highest = findings.stream().map(Finding::severity).min(Comparator.comparingInt(Severity::rank)).orElse(Severity.INFO);
        String summary = NOTE + " " + highest + " - " + findings.size() + " candidate(s)";
        if (!annotations.hasNotes() || !annotations.notes().contains(NOTE)) {
            annotations.setNotes(annotations.hasNotes() && !annotations.notes().isBlank() ? annotations.notes() + " | " + summary : summary);
        }
        if (!annotations.hasHighlightColor() || annotations.highlightColor() == HighlightColor.NONE) {
            annotations.setHighlightColor(switch (highest) {
                case CRITICAL, HIGH -> HighlightColor.RED; case MEDIUM -> HighlightColor.ORANGE; case INFO -> HighlightColor.CYAN;
            });
        }
    }

    public void pause() { paused.set(true); }
    public void resume() { paused.set(false); synchronized (paused) { paused.notifyAll(); } }
    public boolean paused() { return paused.get(); }
    public void clearScanState() {
        cancelQueued(); processed.clear(); rootCounts.clear(); repository.clearResults();
    }
    public void cancelQueued() {
        epoch.incrementAndGet();
        workers.getQueue().clear(); scheduler.getQueue().clear(); scheduled.clear();
        api.logging().logToOutput("JS Secret Hunter: queued work cancelled; in-flight HTTP requests may still finish.");
    }

    public void shutdown() {
        stopping.set(true); resume(); coordinator.shutdownNow(); scheduler.shutdownNow(); workers.shutdownNow();
    }

    private void waitIfPaused() {
        synchronized (paused) {
            while (paused.get() && !stopping.get()) {
                try { paused.wait(500); } catch (InterruptedException error) { Thread.currentThread().interrupt(); return; }
            }
        }
    }

    private static AssetRecord asset(Work w, AssetRecord.AssetStatus status, String detail) {
        return new AssetRecord(w.url, w.parentUrl, w.rootUrl, w.depth, w.chain, status, detail, w.request, w.response, Instant.now());
    }
    private static boolean isJavaScript(HttpRequest req, HttpResponse res, String url) {
        String mime = res.mimeType() == null ? "" : res.mimeType().toString().toLowerCase(Locale.ROOT);
        return AssetDiscovery.isJavaScriptUrl(url) || mime.contains("script") || mime.contains("javascript");
    }
    private static boolean isHtml(HttpResponse res, String url) {
        String mime = res.mimeType() == null ? "" : res.mimeType().toString().toLowerCase(Locale.ROOT);
        String path = url.toLowerCase(Locale.ROOT).split("[?#]", 2)[0];
        return mime.contains("html") || path.endsWith(".html") || path.endsWith(".htm");
    }
    private static boolean isTextual(HttpResponse res) {
        MimeType mime = res.mimeType(); String value = mime == null ? "" : mime.toString().toLowerCase(Locale.ROOT);
        return value.contains("text") || value.contains("json") || value.contains("xml") || value.contains("script") || value.contains("html");
    }
    private static int effectivePort(URI uri) {
        return uri.getPort() >= 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
    }
    private static String canonical(String url) {
        try { URI u = URI.create(url); return new URI(u.getScheme(), u.getUserInfo(), u.getHost(), u.getPort(), u.getPath(), u.getQuery(), null).toString(); }
        catch (Exception invalid) { return url; }
    }
    private static String host(String url) {
        try { return URI.create(url).getHost().toLowerCase(Locale.ROOT); } catch (RuntimeException error) { return "unknown"; }
    }
    private static String safeMessage(Throwable error) {
        String value = error.getMessage(); return value == null || value.isBlank() ? error.getClass().getSimpleName() : value;
    }
    private static Thread daemon(Runnable r, String name) { Thread t = new Thread(r, name); t.setDaemon(true); return t; }

    private record Work(String url, String parentUrl, String rootUrl, int depth, List<String> chain,
                        HttpRequest request, HttpResponse response, boolean root, long epoch) {}
    private record Observed(HttpRequest request, HttpResponse response) {}
}
