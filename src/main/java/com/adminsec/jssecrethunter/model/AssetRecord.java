package com.adminsec.jssecrethunter.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.Instant;
import java.util.List;

public record AssetRecord(
        String url,
        String parentUrl,
        String rootUrl,
        int depth,
        List<String> discoveryChain,
        AssetStatus status,
        String detail,
        HttpRequest request,
        HttpResponse response,
        Instant observedAt) {

    public enum AssetStatus { QUEUED, FETCHING, SCANNED, SKIPPED, FAILED }
}
