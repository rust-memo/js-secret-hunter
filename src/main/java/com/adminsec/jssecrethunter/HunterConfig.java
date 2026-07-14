package com.adminsec.jssecrethunter;

import burp.api.montoya.persistence.Preferences;

public final class HunterConfig {
    private static final String PREFIX = "jsSecretHunter.";
    private boolean autoFetch = true;
    private int maxDepth = 3;
    private int maxAssetsPerRoot = 500;
    private int maxJsBytes = 5 * 1024 * 1024;
    private int maxMapBytes = 10 * 1024 * 1024;
    private int maxTextBytes = 5 * 1024 * 1024;
    private int maxHistoryEntries = 10_000;
    private int maxFindings = 10_000;
    private int workers = 4;
    private int perHost = 2;
    private int timeoutSeconds = 15;
    private ScanScope scanScope = ScanScope.TARGET_SCOPE;

    public static HunterConfig load(Preferences p) {
        HunterConfig c = new HunterConfig();
        c.autoFetch = bool(p, "autoFetch", true);
        c.maxDepth = integer(p, "maxDepth", 3, 0, 10);
        c.maxAssetsPerRoot = integer(p, "maxAssets", 500, 1, 10_000);
        c.maxJsBytes = integer(p, "maxJsMb", 5, 1, 100) * 1024 * 1024;
        c.maxMapBytes = integer(p, "maxMapMb", 10, 1, 200) * 1024 * 1024;
        c.maxTextBytes = integer(p, "maxTextMb", 5, 1, 100) * 1024 * 1024;
        c.maxHistoryEntries = integer(p, "maxHistoryEntries", 10_000, 100, 100_000);
        c.maxFindings = integer(p, "maxFindings", 10_000, 100, 100_000);
        c.workers = integer(p, "workers", 4, 1, 16);
        c.perHost = integer(p, "perHost", 2, 1, 8);
        c.timeoutSeconds = integer(p, "timeout", 15, 3, 120);
        c.scanScope = bool(p, "targetScopeOnly", true) ? ScanScope.TARGET_SCOPE : ScanScope.ALL_TRAFFIC;
        return c;
    }

    public void save(Preferences p) {
        p.setBoolean(PREFIX + "autoFetch", autoFetch);
        p.setInteger(PREFIX + "maxDepth", maxDepth);
        p.setInteger(PREFIX + "maxAssets", maxAssetsPerRoot);
        p.setInteger(PREFIX + "maxJsMb", maxJsBytes / 1024 / 1024);
        p.setInteger(PREFIX + "maxMapMb", maxMapBytes / 1024 / 1024);
        p.setInteger(PREFIX + "maxTextMb", maxTextBytes / 1024 / 1024);
        p.setInteger(PREFIX + "maxHistoryEntries", maxHistoryEntries);
        p.setInteger(PREFIX + "maxFindings", maxFindings);
        p.setInteger(PREFIX + "workers", workers);
        p.setInteger(PREFIX + "perHost", perHost);
        p.setInteger(PREFIX + "timeout", timeoutSeconds);
        p.setBoolean(PREFIX + "targetScopeOnly", scanScope == ScanScope.TARGET_SCOPE);
    }

    private static boolean bool(Preferences p, String key, boolean fallback) {
        Boolean v = p.getBoolean(PREFIX + key); return v == null ? fallback : v;
    }
    private static int integer(Preferences p, String key, int fallback, int min, int max) {
        Integer v = p.getInteger(PREFIX + key); return Math.max(min, Math.min(max, v == null ? fallback : v));
    }

    public boolean autoFetch() { return autoFetch; }
    public void autoFetch(boolean v) { autoFetch = v; }
    public int maxDepth() { return maxDepth; }
    public void maxDepth(int v) { maxDepth = Math.max(0, Math.min(10, v)); }
    public int maxAssetsPerRoot() { return maxAssetsPerRoot; }
    public void maxAssetsPerRoot(int v) { maxAssetsPerRoot = Math.max(1, v); }
    public int maxJsBytes() { return maxJsBytes; }
    public void maxJsBytes(int v) { maxJsBytes = Math.max(64 * 1024, v); }
    public int maxMapBytes() { return maxMapBytes; }
    public void maxMapBytes(int v) { maxMapBytes = Math.max(64 * 1024, v); }
    public int maxTextBytes() { return maxTextBytes; }
    public void maxTextBytes(int v) { maxTextBytes = Math.max(64 * 1024, v); }
    public int maxHistoryEntries() { return maxHistoryEntries; }
    public void maxHistoryEntries(int v) { maxHistoryEntries = Math.max(100, Math.min(100_000, v)); }
    public int maxFindings() { return maxFindings; }
    public void maxFindings(int v) { maxFindings = Math.max(100, Math.min(100_000, v)); }
    public int workers() { return workers; }
    public void workers(int v) { workers = Math.max(1, Math.min(16, v)); }
    public int perHost() { return perHost; }
    public void perHost(int v) { perHost = Math.max(1, Math.min(8, v)); }
    public int timeoutSeconds() { return timeoutSeconds; }
    public void timeoutSeconds(int v) { timeoutSeconds = Math.max(3, Math.min(120, v)); }
    public ScanScope scanScope() { return scanScope; }
    public void scanScope(ScanScope value) { scanScope = value == null ? ScanScope.TARGET_SCOPE : value; }
}
