package com.adminsec.jssecrethunter;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import com.adminsec.jssecrethunter.model.AssetRecord;
import com.adminsec.jssecrethunter.model.Confidence;
import com.adminsec.jssecrethunter.model.Finding;
import com.adminsec.jssecrethunter.model.FindingKind;
import com.adminsec.jssecrethunter.model.ReviewStatus;
import com.adminsec.jssecrethunter.model.Severity;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import javax.swing.SwingUtilities;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class HunterRepositoryTest {
    @Test
    void queuedAndFetchingAssetsBecomeCancelled() {
        HunterRepository repository = new HunterRepository(null);
        repository.upsertAsset(asset("https://app.test/a.js", AssetRecord.AssetStatus.QUEUED));
        repository.upsertAsset(asset("https://app.test/b.js", AssetRecord.AssetStatus.FETCHING));
        repository.upsertAsset(asset("https://app.test/c.js", AssetRecord.AssetStatus.SCANNED));
        repository.cancelActiveAssets("Cancelled by test");
        List<AssetRecord> assets = repository.snapshot().assets();
        assertEquals(2, assets.stream().filter(value -> value.status() == AssetRecord.AssetStatus.CANCELLED).count());
        assertEquals(1, assets.stream().filter(value -> value.status() == AssetRecord.AssetStatus.SCANNED).count());
    }

    @Test
    void coalescesRapidUiNotifications() throws Exception {
        HunterRepository repository = new HunterRepository(null);
        CountDownLatch complete = new CountDownLatch(1);
        AtomicInteger notifications = new AtomicInteger();
        repository.listener(snapshot -> {
            notifications.incrementAndGet();
            if (snapshot.assets().size() == 100) complete.countDown();
        });
        for (int i = 0; i < 100; i++) repository.upsertAsset(asset("https://app.test/" + i + ".js", AssetRecord.AssetStatus.SCANNED));
        assertTrue(complete.await(5, TimeUnit.SECONDS));
        SwingUtilities.invokeAndWait(() -> {});
        assertTrue(notifications.get() < 100);
    }

    @Test
    void persistsOnlyFindingStateAndFingerprints() {
        PersistedObject projectData = mock(PersistedObject.class);
        HunterRepository repository = new HunterRepository(projectData);
        String raw = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345";
        Finding finding = finding(raw);
        repository.addFindings(List.of(finding));
        repository.setStatus(finding, ReviewStatus.REVIEWED);
        repository.markPublished(finding);
        ArgumentCaptor<String> values = ArgumentCaptor.forClass(String.class);
        verify(projectData, atLeastOnce()).setString(anyString(), values.capture());
        assertFalse(values.getAllValues().stream().anyMatch(value -> value != null && value.contains(raw)));
        assertTrue(finding.published());
    }

    @Test
    void updatesEveryFindingInAFileWithOneReviewAction() {
        HunterRepository repository = new HunterRepository(null);
        Finding first = finding("secret-value-one-123456789");
        Finding second = finding("secret-value-two-123456789");
        repository.addFindings(List.of(first, second));

        repository.setStatus(List.of(first, second), ReviewStatus.FALSE_POSITIVE);

        assertEquals(ReviewStatus.FALSE_POSITIVE, first.reviewStatus());
        assertEquals(ReviewStatus.FALSE_POSITIVE, second.reviewStatus());
        assertEquals(2, repository.snapshot().findings().size());
    }

    @Test
    void rejectsWritesFromAnObsoleteScanGeneration() {
        HunterRepository repository = new HunterRepository(null);
        repository.activeGeneration(2);
        repository.addFindings(List.of(finding("obsolete-secret-value-123456")), 1);
        repository.upsertAsset(asset("https://app.test/obsolete.js", AssetRecord.AssetStatus.SCANNED), 1);
        assertTrue(repository.snapshot().findings().isEmpty());
        assertTrue(repository.snapshot().assets().isEmpty());
    }

    private static AssetRecord asset(String url, AssetRecord.AssetStatus status) {
        return new AssetRecord(url, "https://app.test/", "https://app.test/", 1, List.of(url), status,
                "test", null, null, Instant.now());
    }

    private static Finding finding(String raw) {
        return new Finding("openai-api-key", "OpenAI API key", FindingKind.SECRET, Severity.CRITICAL, Confidence.HIGH,
                "https://app.test/app.js", "https://app.test/", List.of("https://app.test/"),
                1, 0, raw.length(), "masked", raw, mock(HttpRequest.class), null);
    }
}
