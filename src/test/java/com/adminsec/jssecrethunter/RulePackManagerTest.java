package com.adminsec.jssecrethunter;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class RulePackManagerTest {
    @Test
    void loadsBundledVersionedRules() {
        RulePackManager manager = new RulePackManager();
        assertEquals("2026.07.2", manager.current().version());
        assertTrue(manager.current().rules().size() >= 35);
        assertEquals(64, manager.current().sha256().length());
    }

    @Test
    void rejectsDuplicateIdsAndUnsupportedRegex() {
        RulePackManager manager = new RulePackManager();
        String duplicate = """
                {"schemaVersion":1,"version":"x","rules":[
                {"id":"same-id","name":"a","kind":"SECRET","severity":"HIGH","confidence":"HIGH","regex":"(a)"},
                {"id":"same-id","name":"b","kind":"SECRET","severity":"HIGH","confidence":"HIGH","regex":"(b)"}]}
                """;
        assertThrows(IllegalArgumentException.class, () -> manager.validate(duplicate.getBytes(StandardCharsets.UTF_8)));
        String lookBehind = """
                {"schemaVersion":1,"version":"x","rules":[
                {"id":"bad-regex","name":"bad","kind":"SECRET","severity":"HIGH","confidence":"HIGH","regex":"(?<=a)(b)"}]}
                """;
        assertThrows(IllegalArgumentException.class, () -> manager.validate(lookBehind.getBytes(StandardCharsets.UTF_8)));
    }
}
