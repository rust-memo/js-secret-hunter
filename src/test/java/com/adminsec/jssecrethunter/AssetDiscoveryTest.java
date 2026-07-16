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

    @Test
    void preservesScriptTypeForExtensionlessAssets() {
        Set<DiscoveredAsset> assets = discovery.discoverAssets("https://app.test/page",
                "<script src='/bundle?v=3'></script><link rel='modulepreload' href='/module'>", true, false);
        assertTrue(assets.stream().anyMatch(asset -> asset.url().equals("https://app.test/bundle?v=3")
                && asset.contentClass() == ContentClass.JAVASCRIPT));
        assertTrue(assets.stream().anyMatch(asset -> asset.url().equals("https://app.test/module")
                && asset.contentClass() == ContentClass.JAVASCRIPT));
    }

    @Test
    void doesNotTurnBareModuleSpecifiersIntoNetworkPaths() {
        Set<DiscoveredAsset> assets = discovery.discoverAssets("https://app.test/assets/app.js",
                "import React from 'react'; import('./runtime');", false, true);
        assertTrue(assets.stream().anyMatch(asset -> asset.url().equals("https://app.test/assets/runtime")));
        assertFalse(assets.stream().anyMatch(asset -> asset.url().equals("https://app.test/assets/react")));
    }

    @Test
    void discoversExportsWorkersAndInlineModuleImports() {
        String js = "export { client } from './client.mjs'; new Worker('/workers/jobs.js');"
                + "navigator.serviceWorker.register('../sw.js');";
        Set<String> urls = discovery.discover("https://app.test/assets/app.js", js, false, true);
        assertTrue(urls.contains("https://app.test/assets/client.mjs"));
        assertTrue(urls.contains("https://app.test/workers/jobs.js"));
        assertTrue(urls.contains("https://app.test/sw.js"));

        String html = "<base href='/static/'><script type='module'>import './boot.js'; new SharedWorker('worker.js')</script>";
        Set<String> inline = discovery.discover("https://app.test/page", html, true, false);
        assertTrue(inline.contains("https://app.test/static/boot.js"));
        assertTrue(inline.contains("https://app.test/static/worker.js"));
    }
}
