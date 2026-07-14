package com.adminsec.jssecrethunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

public final class JsSecretHunterExtension implements BurpExtension {
    private static final String NAME = "JS Secret Hunter";
    private static final String CUSTOM_RULES_KEY = "jsSecretHunter.customRulePack";
    private MontoyaApi api;
    private ScannerService scanner;
    private PersistedObject projectData;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(NAME);
        HunterConfig config = HunterConfig.load(api.persistence().preferences());
        try { projectData = api.persistence().extensionData(); }
        catch (RuntimeException unavailable) {
            projectData = null;
            api.logging().logToOutput("JS Secret Hunter: project persistence unavailable; review state remains in memory.");
        }
        RulePackManager rules = new RulePackManager();
        loadCustomRules(rules);
        HunterRepository repository = new HunterRepository(projectData, config.maxFindings());
        DetectionEngine detector = new DetectionEngine(rules);
        scanner = new ScannerService(api, config, repository, detector);
        HunterPanel panel = new HunterPanel(api, config, repository, rules, scanner, pack -> persistRules(rules, pack));
        api.userInterface().registerSuiteTab("JS Secret Hunter", panel);
        registerContextMenu();
        api.proxy().registerResponseHandler(new LiveProxyHandler());
        api.extension().registerUnloadingHandler(scanner::shutdown);
        api.logging().logToOutput(NAME + " 1.1.1 loaded. Results stay in the extension; optional Proxy notes are disabled by default.");
        api.logging().logToOutput("Active rules: " + rules.current().version() + " (" + rules.current().rules().size() + ", SHA-256 " + rules.current().shortHash() + "…)" );
        scanner.scanHistory();
    }

    private void registerContextMenu() {
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<HttpRequestResponse> messages = new ArrayList<>(event.selectedRequestResponses());
                event.messageEditorRequestResponse().map(value -> value.requestResponse()).ifPresent(message -> {
                    if (!messages.contains(message)) messages.add(message);
                });
                messages.removeIf(message -> message == null || !message.hasResponse());
                if (messages.isEmpty()) return List.of();
                JMenuItem item = new JMenuItem(messages.size() == 1
                        ? "Scan with JS Secret Hunter" : "Scan " + messages.size() + " messages with JS Secret Hunter");
                item.addActionListener(ignored -> {
                    int queued = 0;
                    for (HttpRequestResponse message : messages) if (scanner.scanSelected(message)) queued++;
                    api.logging().logToOutput("JS Secret Hunter: queued " + queued + " selected message(s) for analysis.");
                });
                return List.of(item);
            }
        });
    }

    private void loadCustomRules(RulePackManager rules) {
        if (projectData == null) return;
        try {
            ByteArray stored = projectData.getByteArray(CUSTOM_RULES_KEY);
            if (stored != null && stored.length() > 0) rules.apply(rules.validate(stored.getBytes()));
        } catch (RuntimeException invalid) {
            api.logging().logToError("Stored JS Secret Hunter rule pack is invalid; using bundled rules: " + invalid.getMessage());
        }
    }

    private void persistRules(RulePackManager manager, RulePackManager.LoadedRulePack pack) {
        if (projectData == null) return;
        try {
            if (pack.sha256().equals(manager.bundled().sha256())) projectData.deleteByteArray(CUSTOM_RULES_KEY);
            else projectData.setByteArray(CUSTOM_RULES_KEY, ByteArray.byteArray(pack.source()));
        } catch (RuntimeException error) { api.logging().logToError("Could not persist rule pack: " + error.getMessage()); }
    }

    private final class LiveProxyHandler implements ProxyResponseHandler {
        @Override
        public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
            try { scanner.observe(response.request(), response, response.annotations()); }
            catch (RuntimeException error) { api.logging().logToError("JS Secret Hunter live analysis failed", error); }
            return ProxyResponseReceivedAction.continueWith(response, response.annotations());
        }

        @Override
        public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
            return ProxyResponseToBeSentAction.continueWith(response, response.annotations());
        }
    }
}
