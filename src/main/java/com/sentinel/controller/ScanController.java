package com.sentinel.controller;

import com.sentinel.dto.UrlScanRequest;
import com.sentinel.dto.UrlScanResult;
import com.sentinel.service.UrlScanService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final UrlScanService urlScanService;

    public ScanController(UrlScanService urlScanService) {
        this.urlScanService = urlScanService;
    }

    @GetMapping("/test")
    public String test() {
        return "Sentinel scanner is running!";
    }

    @PostMapping("/url")
    public UrlScanResult scanUrl(@RequestBody UrlScanRequest request) {
        return urlScanService.scan(request.getUrl());
    }
}