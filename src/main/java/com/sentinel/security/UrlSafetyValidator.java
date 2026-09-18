package com.sentinel.security;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;

@Component
public class UrlSafetyValidator {

    public boolean isSafe(String url) {

        try {
            URI uri = URI.create(url);

            // Only allow normal web protocols
            String scheme = uri.getScheme();

            if (!"http".equalsIgnoreCase(scheme)
                    && !"https".equalsIgnoreCase(scheme)) {
                return false;
            }

            String host = uri.getHost();

            if (host == null || host.isBlank()) {
                return false;
            }

            // Explicitly block localhost
            if ("localhost".equalsIgnoreCase(host)) {
                return false;
            }

            // Resolve hostname to IP address(es)
            InetAddress[] addresses = InetAddress.getAllByName(host);

            for (InetAddress address : addresses) {

                if (address.isLoopbackAddress()
                        || address.isSiteLocalAddress()
                        || address.isLinkLocalAddress()
                        || address.isAnyLocalAddress()) {

                    return false;
                }
            }

            return true;

        } catch (Exception exception) {
            return false;
        }
    }
}