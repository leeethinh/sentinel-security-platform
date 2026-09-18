package com.sentinel.util;

import org.springframework.stereotype.Component;

@Component
public class UrlNormalizer {

    public String normalize(String url) {

        if (url == null) {
            return null;
        }

        String normalized = url.trim();

        if (normalized.isEmpty()) {
            return normalized;
        }

        if (!normalized.matches("(?i)^https?://.*")) {
            normalized = "https://" + normalized;
        }

        return normalized;
    }
}