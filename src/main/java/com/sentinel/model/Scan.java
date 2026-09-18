package com.sentinel.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "scans")
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String scanType;

    @Column(length = 2048)
    private String target;

    private String severity;

    private LocalDateTime scannedAt;

    public Scan() {
    }

    public Scan(
            String scanType,
            String target,
            String severity,
            LocalDateTime scannedAt) {

        this.scanType = scanType;
        this.target = target;
        this.severity = severity;
        this.scannedAt = scannedAt;
    }

    public Long getId() {
        return id;
    }

    public String getScanType() {
        return scanType;
    }

    public String getTarget() {
        return target;
    }

    public String getSeverity() {
        return severity;
    }

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }
}