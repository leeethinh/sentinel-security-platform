package com.sentinel.analyzer;

import com.sentinel.dto.SecurityFinding;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@Component
public class UrlRiskAnalyzer {

    public List<SecurityFinding> analyze(String url) {

        List<SecurityFinding> findings = new ArrayList<>();

        try {
            URI uri = URI.create(url);

            checkHttps(uri, findings);
            checkIpAddress(uri, findings);
            checkUrlLength(url, findings);
            checkSuspiciousKeywords(uri, findings);

        } catch (IllegalArgumentException exception) {
            findings.add(new SecurityFinding(
                    "INVALID_URL",
                    "WARNING",
                    "The provided URL is not valid."
            ));
        }

        return findings;
    }

    private void checkHttps(
            URI uri,
            List<SecurityFinding> findings) {

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            findings.add(new SecurityFinding(
                    "HTTPS",
                    "WARNING",
                    "Website does not use HTTPS."
            ));
        }
    }

    private void checkIpAddress(
            URI uri,
            List<SecurityFinding> findings) {

        String host = uri.getHost();

        if (host != null &&
                host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {

            findings.add(new SecurityFinding(
                    "IP_ADDRESS",
                    "WARNING",
                    "URL uses an IP address instead of a domain name."
            ));
        }
    }

    private void checkUrlLength(
            String url,
            List<SecurityFinding> findings) {

        if (url.length() > 100) {
            findings.add(new SecurityFinding(
                    "URL_LENGTH",
                    "INFO",
                    "URL is unusually long."
            ));
        }
    }

    private void checkSuspiciousKeywords(
            URI uri,
            List<SecurityFinding> findings) {

        String value = (
                String.valueOf(uri.getPath()) + " " +
                        String.valueOf(uri.getQuery())
        ).toLowerCase();

        String[] keywords = {
                "login",
                "verify",
                "verification",
                "password",
                "account",
                "secure",
                "update"
        };

        for (String keyword : keywords) {
            if (value.contains(keyword)) {
                findings.add(new SecurityFinding(
                        "SUSPICIOUS_KEYWORD",
                        "INFO",
                        "URL contains potentially sensitive keyword: "
                                + keyword
                ));
            }
        }
    }
}