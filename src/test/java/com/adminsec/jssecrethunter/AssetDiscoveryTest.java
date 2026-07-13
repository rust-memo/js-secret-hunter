package com.adminsec.jssecrethunter;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AssetDiscoveryTest {
    private final AssetDiscovery discovery = new AssetDiscovery();

    @Test
    void discoversHtmlScriptsAndModulePreloads() {
        String html = "<base href='/static/'><script src='app.js'></script>"
                + "<link rel='modulepreload' href='../chunks/a.mjs'>";
        Set<String> urls = discovery.discover("https://app.test/page", html, true, false);
        assertTrue(urls.contains("https://app.test/static/app.js"));
        assertTrue(urls.contains("https://app.test/chunks/a.mjs"));
    }

    @Test
    void discoversImportsChunksAndSourceMaps() {
        String js = "import x from './lib.js'; import('/chunks/42.mjs'); //# sourceMappingURL=app.js.map";
        Set<String> urls = discovery.discover("https://app.test/assets/app.js?v=2", js, false, true);
        assertTrue(urls.contains("https://app.test/assets/lib.js"));
        assertTrue(urls.contains("https://app.test/chunks/42.mjs"));
        assertTrue(urls.contains("https://app.test/assets/app.js.map"));
    }

    @Test
    void rejectsNonHttpSchemesAndStripsFragments() {
        assertNull(AssetDiscovery.resolve("https://a.test/app.js", "data:text/javascript,alert(1)"));
        assertNull(AssetDiscovery.resolve("https://a.test/app.js", "https://user:pass@a.test/private.js"));
        assertEquals("https://a.test/x.js?v=1", AssetDiscovery.resolve("https://a.test/app.js", "/x.js?v=1#frag"));
    }
}
