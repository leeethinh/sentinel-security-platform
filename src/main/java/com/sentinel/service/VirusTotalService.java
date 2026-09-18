package com.sentinel.service;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.sentinel.dto.SecurityFinding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class VirusTotalService {

    private final String apiKey;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public VirusTotalService(
            @Value("${virustotal.api.key}") String apiKey) {
        this.apiKey = apiKey;
    }

    public List<SecurityFinding> analyze(String url) {

        List<SecurityFinding> findings = new ArrayList<>();

        try {
            String urlId = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                            url.getBytes(StandardCharsets.UTF_8)
                    );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(
                            "https://www.virustotal.com/api/v3/urls/" + urlId
                    ))
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            if (response.statusCode() == 404) {
                findings.add(new SecurityFinding(
                        "THREAT_INTELLIGENCE",
                        "INFO",
                        "No existing VirusTotal report was found for this URL."
                ));

                return findings;
            }

            if (response.statusCode() != 200) {
                findings.add(new SecurityFinding(
                        "THREAT_INTELLIGENCE",
                        "INFO",
                        "VirusTotal reputation data could not be retrieved."
                ));

                return findings;
            }

            JsonNode root =
                    objectMapper.readTree(response.body());

            JsonNode stats = root
                    .path("data")
                    .path("attributes")
                    .path("last_analysis_stats");

            int malicious =
                    stats.path("malicious").asInt(0);

            int suspicious =
                    stats.path("suspicious").asInt(0);

            if (malicious > 0) {
                findings.add(new SecurityFinding(
                        "VIRUSTOTAL",
                        "HIGH",
                        malicious +
                                " VirusTotal security engines flagged this URL as malicious."
                ));
            }

            if (suspicious > 0) {
                findings.add(new SecurityFinding(
                        "VIRUSTOTAL",
                        "WARNING",
                        suspicious +
                                " VirusTotal security engines flagged this URL as suspicious."
                ));
            }

            if (malicious == 0 && suspicious == 0) {
                findings.add(new SecurityFinding(
                        "VIRUSTOTAL",
                        "INFO",
                        "No malicious or suspicious detections were reported in the available VirusTotal analysis."
                ));
            }

        } catch (Exception exception) {

            findings.add(new SecurityFinding(
                    "THREAT_INTELLIGENCE",
                    "INFO",
                    "VirusTotal analysis could not be completed."
            ));
        }

        return findings;
    }
    public List<SecurityFinding> analyzeFileHash(String sha256) {

        List<SecurityFinding> findings = new ArrayList<>();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(
                            "https://www.virustotal.com/api/v3/files/" + sha256
                    ))
                    .header("x-apikey", apiKey)
                    .GET()
                    .build();

            HttpResponse<String> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

            if (response.statusCode() == 404) {
                findings.add(new SecurityFinding(
                        "VIRUSTOTAL_FILE",
                        "INFO",
                        "No existing VirusTotal report was found for this file hash."
                ));

                return findings;
            }

            if (response.statusCode() != 200) {
                findings.add(new SecurityFinding(
                        "THREAT_INTELLIGENCE",
                        "INFO",
                        "VirusTotal file reputation data could not be retrieved."
                ));

                return findings;
            }

            JsonNode root =
                    objectMapper.readTree(response.body());

            JsonNode stats = root
                    .path("data")
                    .path("attributes")
                    .path("last_analysis_stats");

            int malicious =
                    stats.path("malicious").asInt(0);

            int suspicious =
                    stats.path("suspicious").asInt(0);

            if (malicious > 0) {
                findings.add(new SecurityFinding(
                        "VIRUSTOTAL_FILE",
                        "HIGH",
                        malicious +
                                " VirusTotal security engines flagged this file as malicious."
                ));
            }

            if (suspicious > 0) {
                findings.add(new SecurityFinding(
                        "VIRUSTOTAL_FILE",
                        "WARNING",
                        suspicious +
                                " VirusTotal security engines flagged this file as suspicious."
                ));
            }

            if (malicious == 0 && suspicious == 0) {
                findings.add(new SecurityFinding(
                        "VIRUSTOTAL_FILE",
                        "INFO",
                        "No malicious or suspicious detections were reported in the available VirusTotal analysis."
                ));
            }

        } catch (Exception exception) {

            findings.add(new SecurityFinding(
                    "THREAT_INTELLIGENCE",
                    "INFO",
                    "VirusTotal file analysis could not be completed."
            ));
        }

        return findings;
    }
}