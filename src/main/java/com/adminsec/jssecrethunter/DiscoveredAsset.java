package com.adminsec.jssecrethunter;

import java.util.Objects;

public record DiscoveredAsset(String url, ContentClass contentClass, String source) {
    public DiscoveredAsset {
        Objects.requireNonNull(url);
        Objects.requireNonNull(contentClass);
        source = source == null ? "discovered" : source;
    }
}
