package com.sentinel.dto;
import java.util.List;
public class UrlScanResult {

    private String url;
    private boolean reachable;
    private boolean https;
    private int statusCode;
    private long responseTimeMs;
    private List<SecurityFinding> findings;

    public UrlScanResult(String url, boolean reachable, boolean https,
                         int statusCode, long responseTimeMs, List<SecurityFinding> findings) {
        this.url = url;
        this.reachable = reachable;
        this.https = https;
        this.statusCode = statusCode;
        this.responseTimeMs = responseTimeMs;
        this.findings = findings;
    }

    public String getUrl() {
        return url;
    }

    public boolean isReachable() {
        return reachable;
    }

    public boolean isHttps() {
        return https;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }
    public List<SecurityFinding> getFindings() {
        return findings;
    }
}