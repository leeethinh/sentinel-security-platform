package com.sentinel.service;

import com.sentinel.analyzer.UrlRiskAnalyzer;
import com.sentinel.dto.SecurityFinding;
import com.sentinel.dto.UrlScanResult;
import com.sentinel.security.UrlSafetyValidator;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

@Service
public class UrlScanService {

    private final UrlRiskAnalyzer urlRiskAnalyzer;
    private final UrlSafetyValidator urlSafetyValidator;
    private final VirusTotalService virusTotalService;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public UrlScanService(
            UrlRiskAnalyzer urlRiskAnalyzer,
            UrlSafetyValidator urlSafetyValidator,
            VirusTotalService virusTotalService) {

        this.urlRiskAnalyzer = urlRiskAnalyzer;
        this.urlSafetyValidator = urlSafetyValidator;
        this.virusTotalService = virusTotalService;
    }

    public UrlScanResult scan(String url) {

        boolean https = url.toLowerCase().startsWith("https://");

        List<SecurityFinding> findings =
                urlRiskAnalyzer.analyze(url);
        if (!urlSafetyValidator.isSafe(url)) {

            findings.add(new SecurityFinding(
                    "UNSAFE_DESTINATION",
                    "BLOCKED",
                    "Sentinel blocked this URL because it targets an invalid, local, or private network destination."
            ));

            return new UrlScanResult(
                    url,
                    false,
                    https,
                    0,
                    0,
                    findings
            );
        }
        findings.addAll(
                virusTotalService.analyze(url)
        );
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