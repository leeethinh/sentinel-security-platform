package com.sentinel.service;

import com.sentinel.dto.SecurityFinding;
import com.sentinel.dto.UrlScanResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class UrlScanService {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public UrlScanResult scan(String url) {

        boolean https = url.toLowerCase().startsWith("https://");
        List<SecurityFinding> findings = new ArrayList<>();

        // Security check #1: HTTPS
        if (!https) {
            findings.add(new SecurityFinding(
                    "HTTPS",
                    "WARNING",
                    "Website does not use HTTPS."
            ));
        }

        long startTime = System.nanoTime();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            HttpResponse<Void> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.discarding()
                    );

            long responseTime =
                    (System.nanoTime() - startTime) / 1_000_000;

            // Security check #2: HTTP errors
            if (response.statusCode() >= 400) {
                findings.add(new SecurityFinding(
                        "HTTP_STATUS",
                        "WARNING",
                        "Website returned HTTP status "
                                + response.statusCode() + "."
                ));
            }

            return new UrlScanResult(
                    url,
                    true,
                    https,
                    response.statusCode(),
                    responseTime,
                    findings
            );

        } catch (Exception exception) {

            long responseTime =
                    (System.nanoTime() - startTime) / 1_000_000;

            findings.add(new SecurityFinding(
                    "CONNECTION",
                    "WARNING",
                    "Sentinel could not reach the website."
            ));

            return new UrlScanResult(
                    url,
                    false,
                    https,
                    0,
                    responseTime,
                    findings
            );
        }
    }
}