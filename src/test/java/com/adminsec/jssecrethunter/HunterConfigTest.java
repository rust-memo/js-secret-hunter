package com.adminsec.jssecrethunter;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HunterConfigTest {
    @Test
    void targetScopeIsTheSafeDefaultAndIsPersisted() {
        Preferences preferences = mock(Preferences.class);
        when(preferences.getBoolean("jsSecretHunter.targetScopeOnly")).thenReturn(null);
        HunterConfig config = HunterConfig.load(preferences);
        assertEquals(ScanScope.TARGET_SCOPE, config.scanScope());
        org.junit.jupiter.api.Assertions.assertFalse(config.annotateHistory());
        config.scanScope(ScanScope.ALL_TRAFFIC);
        config.annotateHistory(true);
        config.save(preferences);
        verify(preferences).setBoolean("jsSecretHunter.targetScopeOnly", false);
        verify(preferences).setBoolean("jsSecretHunter.annotateHistory", true);
    }

    @Test
    void loadsExplicitAllTrafficPreference() {
        Preferences preferences = mock(Preferences.class);
        when(preferences.getBoolean("jsSecretHunter.targetScopeOnly")).thenReturn(false);
        HunterConfig config = HunterConfig.load(preferences);
        assertEquals(ScanScope.ALL_TRAFFIC, config.scanScope());
    }
}
