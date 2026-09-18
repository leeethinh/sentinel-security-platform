package com.sentinel.dto;

import java.util.List;

public class FileScanResult {

    private String fileName;
    private long sizeBytes;
    private String contentType;
    private String sha256;
    private List<SecurityFinding> findings;

    public FileScanResult(
            String fileName,
            long sizeBytes,
            String contentType,
            String sha256,
            List<SecurityFinding> findings) {

        this.fileName = fileName;
        this.sizeBytes = sizeBytes;
        this.contentType = contentType;
        this.sha256 = sha256;
        this.findings = findings;
    }

    public String getFileName() {
        return fileName;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getContentType() {
        return contentType;
    }

    public String getSha256() {
        return sha256;
    }

    public List<SecurityFinding> getFindings() {
        return findings;
    }
}