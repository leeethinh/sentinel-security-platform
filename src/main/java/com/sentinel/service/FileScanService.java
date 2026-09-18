package com.sentinel.service;

import com.sentinel.dto.FileScanResult;
import com.sentinel.dto.SecurityFinding;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

@Service
public class FileScanService {
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024;
    private final VirusTotalService virusTotalService;

    public FileScanService(VirusTotalService virusTotalService) {
        this.virusTotalService = virusTotalService;
    }

    public FileScanResult scan(MultipartFile file) {

        List<SecurityFinding> findings = new ArrayList<>();

        if (file.isEmpty()) {
            findings.add(new SecurityFinding(
                    "EMPTY_FILE",
                    "WARNING",
                    "The uploaded file is empty."
            ));

            return new FileScanResult(
                    file.getOriginalFilename(),
                    0,
                    file.getContentType(),
                    null,
                    findings
            );
        }
        if (file.getSize() > MAX_FILE_SIZE) {

            findings.add(new SecurityFinding(
                    "FILE_SIZE",
                    "BLOCKED",
                    "File exceeds Sentinel's 10 MB upload limit."
            ));

            return new FileScanResult(
                    file.getOriginalFilename(),
                    file.getSize(),
                    file.getContentType(),
                    null,
                    findings
            );
        }
        try {
            String sha256 = calculateSha256(file);
            findings.addAll(
                    virusTotalService.analyzeFileHash(sha256)
            );
            return new FileScanResult(
                    file.getOriginalFilename(),
                    file.getSize(),
                    file.getContentType(),
                    sha256,
                    findings
            );

        } catch (Exception exception) {

            findings.add(new SecurityFinding(
                    "FILE_PROCESSING",
                    "WARNING",
                    "Sentinel could not process the uploaded file."
            ));

            return new FileScanResult(
                    file.getOriginalFilename(),
                    file.getSize(),
                    file.getContentType(),
                    null,
                    findings
            );
        }
    }

    private String calculateSha256(MultipartFile file)
            throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance("SHA-256");

        try (var inputStream = file.getInputStream()) {

            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        byte[] hash = digest.digest();

        return HexFormat.of().formatHex(hash);
    }
}