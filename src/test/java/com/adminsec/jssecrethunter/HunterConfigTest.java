package com.adminsec.jssecrethunter;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HunterConfigTest {
    @Test
    void allHistoryLocalAnalysisIsTheDefaultAndIsPersisted() {
        Preferences preferences = mock(Preferences.class);
        when(preferences.getBoolean("jsSecretHunter.scanAllHistory")).thenReturn(null);
        HunterConfig config = HunterConfig.load(preferences);
        assertEquals(ScanScope.ALL_TRAFFIC, config.scanScope());
        org.junit.jupiter.api.Assertions.assertFalse(config.annotateHistory());
        assertEquals("jquery, google-analytics, gpt.js", config.assetExclusions());
        config.scanScope(ScanScope.TARGET_SCOPE);
        config.annotateHistory(true);
        config.save(preferences);
        verify(preferences).setBoolean("jsSecretHunter.scanAllHistory", false);
        verify(preferences).setBoolean("jsSecretHunter.targetScopeOnly", true);
        verify(preferences).setBoolean("jsSecretHunter.annotateHistory", true);
        verify(preferences).setString("jsSecretHunter.assetExclusions", "jquery, google-analytics, gpt.js");
    }

    @Test
    void loadsExplicitTargetScopePreferenceFromTheNewKey() {
        Preferences preferences = mock(Preferences.class);
        when(preferences.getBoolean("jsSecretHunter.scanAllHistory")).thenReturn(false);
        HunterConfig config = HunterConfig.load(preferences);
        assertEquals(ScanScope.TARGET_SCOPE, config.scanScope());
    }

    @Test
    void migratesTheOldScopeDefaultToAllHistory() {
        Preferences preferences = mock(Preferences.class);
        when(preferences.getBoolean("jsSecretHunter.scanAllHistory")).thenReturn(null);
        when(preferences.getBoolean("jsSecretHunter.targetScopeOnly")).thenReturn(true);
        assertEquals(ScanScope.ALL_TRAFFIC, HunterConfig.load(preferences).scanScope());
    }

    @Test
    void matchesConfigurableAssetExclusionsCaseInsensitively() {
        HunterConfig config = new HunterConfig();
        config.assetExclusions("jquery.min.js, analytics/vendor\nreact.production");
        assertEquals("jquery.min.js", config.assetExclusionFor("https://cdn.test/JQUERY.MIN.JS?v=3").orElseThrow());
        assertTrue(config.assetExclusionFor("https://cdn.test/app.js").isEmpty());
        config.assetExclusions("");
        assertTrue(config.assetExclusionFor("https://cdn.test/jquery.min.js").isEmpty());
    }
}
