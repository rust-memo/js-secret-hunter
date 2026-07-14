package com.adminsec.jssecrethunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.adminsec.jssecrethunter.model.AssetRecord;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.Severity;

import javax.swing.SwingUtilities;
import javax.swing.Timer;

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
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

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
    private final Map<String, Observed> observedCache = new ConcurrentHashMap<>();
    private final Map<String, Semaphore> hostLimits = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> rootCounts = new ConcurrentHashMap<>();
    private final Map<String, Annotations> rootAnnotations = new ConcurrentHashMap<>();
    private final Set<String> discoveredPerRoot = ConcurrentHashMap.newKeySet();
    private final Set<String> scheduled = ConcurrentHashMap.newKeySet();
    private final Set<String> processed = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean paused = new AtomicBoolean(false);
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final AtomicBoolean historyScanning = new AtomicBoolean(false);
    private final AtomicInteger inFlight = new AtomicInteger();
    private final AtomicLong scanned = new AtomicLong();
    private final AtomicLong epoch = new AtomicLong();
    private final AtomicLong stateVersion = new AtomicLong();
    private final AtomicBoolean stateNotificationPending = new AtomicBoolean();
    private volatile Consumer<ScanState> stateListener = ignored -> {};
    private volatile String stateMessage = "Idle";

    public ScannerService(MontoyaApi api, HunterConfig config, HunterRepository repository, DetectionEngine detector) {
        this.api = api; this.config = config; this.repository = repository; this.detector = detector;
        workers = (ThreadPoolExecutor) Executors.newFixedThreadPool(config.workers(), r -> daemon(r, "js-secret-hunter-worker"));
        coordinator = Executors.newSingleThreadExecutor(r -> daemon(r, "js-secret-hunter-history"));
        scheduler = new ScheduledThreadPoolExecutor(1, r -> daemon(r, "js-secret-hunter-delay"));
        scheduler.setRemoveOnCancelPolicy(true);
    }

    public void stateListener(Consumer<ScanState> listener) {
        stateListener = listener == null ? ignored -> {} : listener;
        publishState();
    }

    public void scanHistory() { submitHistoryScan(epoch.get()); }

    public void restartHistoryScan() {
        long generation = beginNewGeneration(true, "Restarting history scan");
        submitHistoryScan(generation);
    }

    private void submitHistoryScan(long generation) {
        try { coordinator.submit(() -> scanHistory(generation)); }
        catch (RejectedExecutionException ignored) { }
    }

    private void scanHistory(long generation) {
        if (generation != epoch.get() || stopping.get()) return;
        historyScanning.set(true); stateMessage = "Reading Proxy history"; publishState();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history(item -> item.finalRequest() != null && item.hasResponse()
                    && (config.scanScope() == ScanScope.ALL_TRAFFIC || inScope(item.finalRequest())));
            int total = history.size();
            if (total > config.maxHistoryEntries()) {
                history = new ArrayList<>(history.subList(total - config.maxHistoryEntries(), total));
                stateMessage = "Scanning the newest " + history.size() + " of " + total + " matching history entries";
            }
            for (ProxyHttpRequestResponse item : history) {
                if (stopping.get() || generation != epoch.get()) return;
                if (!waitIfPaused(generation)) return;
                observeInternal(item.finalRequest(), item.response(), item.annotations(), generation, true);
            }
            stateMessage = "Queued " + history.size() + " history entries";
            api.logging().logToOutput("JS Secret Hunter: queued history scan for " + history.size() + " entries.");
        } catch (RuntimeException error) {
            stateMessage = "History scan failed: " + safeMessage(error);
            api.logging().logToError("JS Secret Hunter history scan failed", error);
        } finally {
            historyScanning.set(false); publishState();
        }
    }

    public void observe(HttpRequest request, HttpResponse response, Annotations annotations) {
        if (request == null || response == null || stopping.get()) return;
        if (config.scanScope() == ScanScope.TARGET_SCOPE && !inScope(request)) return;
        observeInternal(request, response, annotations, epoch.get(), true);
    }

    public boolean scanSelected(HttpRequestResponse message) {
        if (message == null || !message.hasResponse() || message.request() == null || message.response() == null) return false;
        boolean expand = inScope(message.request());
        observeInternal(message.request(), message.response(), message.annotations(), epoch.get(), expand);
        stateMessage = expand ? "Queued selected message" : "Queued selected message for local-only analysis";
        publishState();
        return true;
    }

    private void observeInternal(HttpRequest request, HttpResponse response, Annotations annotations,
                                 long generation, boolean expand) {
        if (generation != epoch.get() || stopping.get()) return;
        String url = canonical(request.url());
        Observed stored = temporaryObserved(request, response);
        observedCache.put(url, stored); trimCache(observedCache, config.maxHistoryEntries() * 2);
        if (annotations != null) { rootAnnotations.putIfAbsent(url, annotations); trimCache(rootAnnotations, config.maxHistoryEntries()); }
        submitWorker(() -> process(new Work(url, url, url, 0, List.of(url), stored.request, stored.response, generation, expand, null)));
    }

    private void submitWorker(Runnable action) {
        try {
            workers.submit(() -> {
                inFlight.incrementAndGet(); publishState();
                try { action.run(); }
                catch (RuntimeException error) { api.logging().logToError("JS Secret Hunter background task failed", error); }
                finally { inFlight.decrementAndGet(); publishState(); }
            });
            publishState();
        } catch (RejectedExecutionException ignored) { }
    }

    private void process(Work work) {
        if (stopping.get() || work.epoch != epoch.get() || !waitIfPaused(work.epoch)) return;
        String processKey = work.rootUrl + "\n" + canonical(work.url) + "\n" + work.response.statusCode() + "\n" + work.response.body().length();
        if (!processed.add(processKey)) return;
        ContentClass contentClass = classify(work.request, work.response, work.url, work.hint);
        if (contentClass == ContentClass.BINARY) {
            if (work.epoch == epoch.get()) repository.upsertAsset(asset(work, AssetRecord.AssetStatus.SKIPPED, "Non-text response"), work.epoch);
            return;
        }
        int limit = switch (contentClass) {
            case SOURCE_MAP -> config.maxMapBytes();
            case JAVASCRIPT -> config.maxJsBytes();
            default -> config.maxTextBytes();
        };
        String body = TextBody.decode(work.response, limit);
        if (body == null) {
            if (work.epoch == epoch.get()) repository.upsertAsset(asset(work, AssetRecord.AssetStatus.SKIPPED, "Unsupported encoding or size limit"), work.epoch);
            return;
        }

        if (work.epoch != epoch.get()) return;
        List<Finding> findings = detector.scan(body, work.url, work.rootUrl, work.chain, work.request, work.response);
        if (work.epoch != epoch.get()) return;
        repository.addFindings(findings, work.epoch);
        repository.upsertAsset(asset(work, AssetRecord.AssetStatus.SCANNED,
                findings.size() + " findings; " + body.length() + " chars; " + contentClass.name().toLowerCase(Locale.ROOT)), work.epoch);
        scanned.incrementAndGet(); annotate(work.rootUrl, findings); publishState();

        if (!work.expand || work.depth >= config.maxDepth()) return;
        boolean html = contentClass == ContentClass.HTML;
        boolean javascript = contentClass == ContentClass.JAVASCRIPT || contentClass == ContentClass.SOURCE_MAP;
        if (!html && !javascript) return;
        for (DiscoveredAsset link : discovery.discoverAssets(work.url, body, html, javascript)) scheduleLink(work, link);
    }

    private Observed temporaryObserved(HttpRequest request, HttpResponse response) {
        try {
            HttpRequestResponse stored = HttpRequestResponse.httpRequestResponse(request, response).copyToTempFile();
            return new Observed(stored.request(), stored.response());
        } catch (RuntimeException unavailable) { return new Observed(request, response); }
    }

    private void scheduleLink(Work parent, DiscoveredAsset link) {
        if (parent.epoch != epoch.get() || stopping.get()) return;
        String canonical = canonical(link.url());
        String rootKey = parent.rootUrl + "\n" + canonical;
        if (!discoveredPerRoot.add(rootKey)) return;
        AtomicInteger count = rootCounts.computeIfAbsent(parent.rootUrl, ignored -> new AtomicInteger());
        if (count.incrementAndGet() > config.maxAssetsPerRoot()) return;
        List<String> chain = new ArrayList<>(parent.chain); chain.add(link.url());
        Observed observed = observedCache.get(canonical);
        if (observed != null) {
            process(new Work(link.url(), parent.url, parent.rootUrl, parent.depth + 1, chain,
                    observed.request, observed.response, parent.epoch, true, link.contentClass()));
            return;
        }
        if (!config.autoFetch()) return;
        HttpRequest scopeProbe;
        try { scopeProbe = HttpRequest.httpRequestFromUrl(link.url()); }
        catch (RuntimeException invalid) { return; }
        if (!inScope(scopeProbe)) {
            if (parent.epoch != epoch.get()) return;
            repository.upsertAsset(new AssetRecord(link.url(), parent.url, parent.rootUrl, parent.depth + 1, chain,
                    AssetRecord.AssetStatus.SKIPPED, "Outside Target Scope", scopeProbe, null, Instant.now()), parent.epoch);
            return;
        }
        if (!scheduled.add(rootKey)) return;
        if (parent.epoch != epoch.get()) { scheduled.remove(rootKey); return; }
        repository.upsertAsset(new AssetRecord(link.url(), parent.url, parent.rootUrl, parent.depth + 1, chain,
                AssetRecord.AssetStatus.QUEUED, link.source() + "; waiting for background fetch", scopeProbe, null, Instant.now()), parent.epoch);
        scheduler.schedule(() -> {
            if (parent.epoch != epoch.get()) return;
            Observed late = observedCache.get(canonical);
            if (late != null) {
                submitWorker(() -> process(new Work(link.url(), parent.url, parent.rootUrl, parent.depth + 1, chain,
                        late.request, late.response, parent.epoch, true, link.contentClass())));
            } else {
                submitWorker(() -> fetch(link.url(), parent, chain, 0, link.contentClass()));
            }
        }, 500, TimeUnit.MILLISECONDS);
        publishState();
    }

    private void fetch(String url, Work parent, List<String> chain, int redirects, ContentClass hint) {
        if (!waitIfPaused(parent.epoch) || stopping.get() || parent.epoch != epoch.get()) return;
        HttpRequest request = requestFor(url, parent.request);
        if (!inScope(request)) return;
        Semaphore limit = hostLimits.computeIfAbsent(host(url), ignored -> new Semaphore(config.perHost()));
        boolean acquired = false;
        try {
            limit.acquire(); acquired = true;
            if (parent.epoch != epoch.get()) return;
            repository.upsertAsset(new AssetRecord(url, parent.url, parent.rootUrl, parent.depth + 1, chain,
                    AssetRecord.AssetStatus.FETCHING, "GET in progress", request, null, Instant.now()), parent.epoch);
            HttpRequestResponse rr = api.http().sendRequest(request, RequestOptions.requestOptions()
                    .withRedirectionMode(RedirectionMode.NEVER).withResponseTimeout(config.timeoutSeconds() * 1000L));
            if (parent.epoch != epoch.get()) return;
            if (rr == null || !rr.hasResponse()) {
                repository.upsertAsset(new AssetRecord(url, parent.url, parent.rootUrl, parent.depth + 1, chain,
                        AssetRecord.AssetStatus.FAILED, "No response", request, null, Instant.now()), parent.epoch); return;
            }
            HttpResponse response = rr.response();
            if (response.statusCode() >= 300 && response.statusCode() < 400 && response.hasHeader("Location") && redirects < 3) {
                String target = AssetDiscovery.resolve(url, response.headerValue("Location"));
                if (target != null) {
                    HttpRequest probe = HttpRequest.httpRequestFromUrl(target);
                    if (inScope(probe)) {
                        List<String> redirected = new ArrayList<>(chain); redirected.add(target);
                        limit.release(); acquired = false;
                        fetch(target, new Work(url, parent.url, parent.rootUrl, parent.depth, chain,
                                request, response, parent.epoch, true, hint), redirected, redirects + 1, hint);
                        return;
                    }
                }
            }
            HttpRequestResponse stored = rr.copyToTempFile();
            observedCache.put(canonical(url), new Observed(stored.request(), stored.response()));
            process(new Work(url, parent.url, parent.rootUrl, parent.depth + 1, chain,
                    stored.request(), stored.response(), parent.epoch, true, hint));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException error) {
            if (parent.epoch == epoch.get()) {
                repository.upsertAsset(new AssetRecord(url, parent.url, parent.rootUrl, parent.depth + 1, chain,
                        AssetRecord.AssetStatus.FAILED, safeMessage(error), request, null, Instant.now()), parent.epoch);
            }
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
        return target.withUpdatedHeader("Accept", "application/javascript, text/javascript, application/json, text/*, */*;q=0.8");
    }

    static boolean sameOrigin(String left, String right) {
        try {
            URI a = URI.create(left), b = URI.create(right);
            return a.getScheme().equalsIgnoreCase(b.getScheme()) && a.getHost().equalsIgnoreCase(b.getHost())
                    && effectivePort(a) == effectivePort(b);
        } catch (RuntimeException error) { return false; }
    }

    static ContentClass classify(HttpRequest req, HttpResponse res, String url) {
        return classify(req, res, url, null);
    }

    private static ContentClass classify(HttpRequest req, HttpResponse res, String url, ContentClass hint) {
        if (AssetDiscovery.isSourceMapUrl(url)) return ContentClass.SOURCE_MAP;
        String mime = res.mimeType() == null ? "" : res.mimeType().toString().toLowerCase(Locale.ROOT);
        String contentType = res.hasHeader("Content-Type") && res.headerValue("Content-Type") != null
                ? res.headerValue("Content-Type").toLowerCase(Locale.ROOT) : "";
        String path = url.toLowerCase(Locale.ROOT).split("[?#]", 2)[0];
        if (hint == ContentClass.SOURCE_MAP) return ContentClass.SOURCE_MAP;
        if (hint == ContentClass.JAVASCRIPT || AssetDiscovery.isJavaScriptUrl(url) || mime.contains("script") || mime.contains("javascript")
                || contentType.contains("javascript") || contentType.contains("ecmascript")) return ContentClass.JAVASCRIPT;
        if (mime.contains("html") || contentType.contains("html") || path.endsWith(".html") || path.endsWith(".htm")) return ContentClass.HTML;
        if (mime.contains("json") || contentType.contains("json") || path.endsWith(".json")) return ContentClass.JSON;
        if (mime.contains("xml") || contentType.contains("xml") || path.endsWith(".xml")) return ContentClass.XML;
        if (mime.contains("text") || contentType.startsWith("text/")) return ContentClass.TEXT;
        return ContentClass.BINARY;
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

    public void pause() { paused.set(true); stateMessage = "Paused"; publishState(); }
    public void resume() { paused.set(false); synchronized (paused) { paused.notifyAll(); } stateMessage = "Resumed"; publishState(); }
    public boolean paused() { return paused.get(); }

    public void clearScanState() { beginNewGeneration(true, "Results cleared"); }

    public void cancelQueued() { beginNewGeneration(false, "Queued work cancelled"); }

    public void reconfigure() {
        hostLimits.clear(); observedCache.clear(); rootAnnotations.clear();
        stateMessage = "Settings applied";
        publishState();
    }

    private long beginNewGeneration(boolean clearResults, String message) {
        stateMessage = message;
        long generation = epoch.incrementAndGet();
        repository.activeGeneration(generation);
        workers.getQueue().clear(); scheduler.getQueue().clear();
        scheduled.clear(); discoveredPerRoot.clear(); processed.clear(); rootCounts.clear();
        if (clearResults) rootAnnotations.clear();
        repository.cancelActiveAssets(message);
        if (clearResults) { repository.clearResults(); scanned.set(0); }
        api.logging().logToOutput("JS Secret Hunter: " + message + "; in-flight HTTP requests will be ignored when they finish.");
        publishState();
        return generation;
    }

    public void shutdown() {
        stopping.set(true); long generation = epoch.incrementAndGet(); repository.activeGeneration(generation); resume();
        coordinator.shutdownNow(); scheduler.shutdownNow(); workers.shutdownNow();
        stateMessage = "Stopped"; publishState();
    }

    private boolean waitIfPaused(long generation) {
        synchronized (paused) {
            while (paused.get() && !stopping.get() && generation == epoch.get()) {
                try { paused.wait(250); }
                catch (InterruptedException error) { Thread.currentThread().interrupt(); return false; }
            }
        }
        return !stopping.get() && generation == epoch.get();
    }

    private void publishState() {
        stateVersion.incrementAndGet();
        scheduleStateNotification();
    }

    private void scheduleStateNotification() {
        if (!stateNotificationPending.compareAndSet(false, true)) return;
        SwingUtilities.invokeLater(() -> {
            Timer timer = new Timer(50, ignored -> deliverStateNotification());
            timer.setRepeats(false); timer.start();
        });
    }

    private void deliverStateNotification() {
        long delivered = stateVersion.get();
        try { stateListener.accept(currentState()); }
        catch (RuntimeException error) { api.logging().logToError("JS Secret Hunter state listener failed", error); }
        finally {
            stateNotificationPending.set(false);
            if (stateVersion.get() != delivered) scheduleStateNotification();
        }
    }

    private ScanState currentState() {
        ScanState.Phase phase;
        if (stopping.get()) phase = ScanState.Phase.STOPPED;
        else if (paused.get()) phase = ScanState.Phase.PAUSED;
        else if (historyScanning.get() || inFlight.get() > 0 || !workers.getQueue().isEmpty() || !scheduler.getQueue().isEmpty()) phase = ScanState.Phase.SCANNING;
        else phase = ScanState.Phase.IDLE;
        int queued = workers.getQueue().size() + scheduler.getQueue().size();
        return new ScanState(phase, queued, inFlight.get(), scanned.get(), repository.findingCount(), stateMessage);
    }

    private static AssetRecord asset(Work w, AssetRecord.AssetStatus status, String detail) {
        return new AssetRecord(w.url, w.parentUrl, w.rootUrl, w.depth, w.chain, status, detail, w.request, w.response, Instant.now());
    }
    private static int effectivePort(URI uri) {
        return uri.getPort() >= 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
    }
    private static String canonical(String url) {
        try { URI u = URI.create(url); return new URI(u.getScheme(), u.getUserInfo(), u.getHost(), u.getPort(), u.getPath(), u.getQuery(), null).toString(); }
        catch (Exception invalid) { return url; }
    }
    private static String host(String url) {
        try { String host = URI.create(url).getHost(); return host == null ? "unknown" : host.toLowerCase(Locale.ROOT); }
        catch (RuntimeException error) { return "unknown"; }
    }
    private static String safeMessage(Throwable error) {
        String value = error.getMessage(); return value == null || value.isBlank() ? error.getClass().getSimpleName() : value;
    }
    private static boolean inScope(HttpRequest request) {
        try { return request != null && request.isInScope(); }
        catch (RuntimeException unavailable) { return false; }
    }
    private static <K, V> void trimCache(Map<K, V> cache, int maximum) {
        int limit = Math.max(100, maximum);
        while (cache.size() > limit) {
            var iterator = cache.keySet().iterator();
            if (!iterator.hasNext()) return;
            cache.remove(iterator.next());
        }
    }
    private static Thread daemon(Runnable r, String name) { Thread t = new Thread(r, name); t.setDaemon(true); return t; }

    private record Work(String url, String parentUrl, String rootUrl, int depth, List<String> chain,
                        HttpRequest request, HttpResponse response, long epoch, boolean expand, ContentClass hint) {}
    private record Observed(HttpRequest request, HttpResponse response) {}
}
