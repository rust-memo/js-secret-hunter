package com.adminsec.jssecrethunter;

import burp.api.montoya.persistence.PersistedObject;
import com.adminsec.jssecrethunter.model.AssetRecord;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.ReviewStatus;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Predicate;

public final class HunterRepository {
    private static final String REVIEWED = "reviewed";
    private static final String FALSE_POSITIVES = "falsePositives";
    private static final String IGNORED_RULES = "ignoredRules";
    private static final String IGNORED_HOSTS = "ignoredHosts";
    private final Map<String, Finding> findings = new LinkedHashMap<>();
    private final Map<String, AssetRecord> assets = new LinkedHashMap<>();
    private final Set<String> reviewed = ConcurrentHashMap.newKeySet();
    private final Set<String> falsePositives = ConcurrentHashMap.newKeySet();
    private final Set<String> ignoredRules = ConcurrentHashMap.newKeySet();
    private final Set<String> ignoredHosts = ConcurrentHashMap.newKeySet();
    private final PersistedObject projectData;
    private volatile Consumer<Snapshot> listener = ignored -> {};

    public HunterRepository(PersistedObject projectData) {
        this.projectData = projectData;
        load(REVIEWED, reviewed); load(FALSE_POSITIVES, falsePositives);
        load(IGNORED_RULES, ignoredRules); load(IGNORED_HOSTS, ignoredHosts);
    }

    public void listener(Consumer<Snapshot> listener) { this.listener = listener == null ? ignored -> {} : listener; }

    public void addFindings(Collection<Finding> additions) {
        boolean changed = false;
        synchronized (findings) {
            for (Finding f : additions) {
                if (ignoredRules.contains(f.ruleId()) || ignoredHosts.contains(host(f.assetUrl())) || findings.containsKey(f.fingerprint())) continue;
                if (reviewed.contains(f.fingerprint())) f.reviewStatus(ReviewStatus.REVIEWED);
                if (falsePositives.contains(f.fingerprint())) f.reviewStatus(ReviewStatus.FALSE_POSITIVE);
                findings.put(f.fingerprint(), f); changed = true;
            }
        }
        if (changed) notifyListener();
    }

    public void upsertAsset(AssetRecord asset) {
        synchronized (assets) { assets.put(asset.url(), asset); }
        notifyListener();
    }

    public Snapshot snapshot() {
        synchronized (findings) {
            synchronized (assets) { return new Snapshot(new ArrayList<>(findings.values()), new ArrayList<>(assets.values())); }
        }
    }

    public void clearResults() {
        synchronized (findings) { findings.clear(); }
        synchronized (assets) { assets.clear(); }
        notifyListener();
    }

    public void setStatus(Finding finding, ReviewStatus status) {
        finding.reviewStatus(status);
        reviewed.remove(finding.fingerprint()); falsePositives.remove(finding.fingerprint());
        if (status == ReviewStatus.REVIEWED) reviewed.add(finding.fingerprint());
        if (status == ReviewStatus.FALSE_POSITIVE) falsePositives.add(finding.fingerprint());
        persist(); notifyListener();
    }

    public void ignoreRule(String ruleId) {
        ignoredRules.add(ruleId);
        removeIf(f -> f.ruleId().equals(ruleId)); persist();
    }

    public void ignoreHost(String host) {
        if (host == null || host.isBlank()) return;
        ignoredHosts.add(host.toLowerCase());
        removeIf(f -> host(f.assetUrl()).equalsIgnoreCase(host)); persist();
    }

    public Set<String> ignoredRules() { return Set.copyOf(ignoredRules); }
    public Set<String> ignoredHosts() { return Set.copyOf(ignoredHosts); }

    public void restoreIgnores() {
        ignoredRules.clear(); ignoredHosts.clear(); persist(); notifyListener();
    }

    private void removeIf(Predicate<Finding> predicate) {
        synchronized (findings) { findings.values().removeIf(predicate); }
        notifyListener();
    }

    private void load(String key, Set<String> target) {
        if (projectData == null) return;
        try {
            String value = projectData.getString("jsSecretHunter." + key);
            if (value != null) value.lines().filter(v -> !v.isBlank()).forEach(target::add);
        } catch (RuntimeException ignored) { }
    }

    private void persist() {
        if (projectData == null) return;
        try {
            projectData.setString("jsSecretHunter." + REVIEWED, String.join("\n", reviewed));
            projectData.setString("jsSecretHunter." + FALSE_POSITIVES, String.join("\n", falsePositives));
            projectData.setString("jsSecretHunter." + IGNORED_RULES, String.join("\n", ignoredRules));
            projectData.setString("jsSecretHunter." + IGNORED_HOSTS, String.join("\n", ignoredHosts));
        } catch (RuntimeException ignored) { }
    }

    private void notifyListener() {
        Snapshot value = snapshot();
        SwingUtilities.invokeLater(() -> listener.accept(value));
    }

    private static String host(String url) {
        try { return java.net.URI.create(url).getHost() == null ? "" : java.net.URI.create(url).getHost().toLowerCase(); }
        catch (RuntimeException invalid) { return ""; }
    }

    public record Snapshot(List<Finding> findings, List<AssetRecord> assets) {}
}
