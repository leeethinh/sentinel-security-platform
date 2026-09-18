package com.sentinel.repository;

import com.sentinel.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanRepository
        extends JpaRepository<Scan, Long> {

    List<Scan> findAllByOrderByScannedAtDesc();
}