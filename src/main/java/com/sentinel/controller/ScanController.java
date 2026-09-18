package com.sentinel.controller;

import com.sentinel.dto.UrlScanRequest;
import com.sentinel.dto.UrlScanResult;
import com.sentinel.service.UrlScanService;
import org.springframework.web.bind.annotation.*;
import com.sentinel.dto.FileScanResult;
import com.sentinel.service.FileScanService;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final UrlScanService urlScanService;
    private final FileScanService fileScanService;
    public ScanController(
            UrlScanService urlScanService,
            FileScanService fileScanService) {

        this.urlScanService = urlScanService;
        this.fileScanService = fileScanService;
    }

    @GetMapping("/test")
    public String test() {
        return "Sentinel scanner is running!";
    }

    @PostMapping("/url")
    public UrlScanResult scanUrl(@RequestBody UrlScanRequest request) {
        return urlScanService.scan(request.getUrl());
    }
    @PostMapping("/file")
    public FileScanResult scanFile(
            @RequestParam("file") MultipartFile file) {

        return fileScanService.scan(file);
    }
}