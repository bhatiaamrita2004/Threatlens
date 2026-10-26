package com.threatlens.backend.repository;

import com.threatlens.backend.domain.AlertEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AlertRepository extends JpaRepository<AlertEntity, String> {

    Page<AlertEntity> findByBand(String band, Pageable pageable);

    Page<AlertEntity> findByStatus(String status, Pageable pageable);

    Page<AlertEntity> findByBandAndStatus(String band, String status, Pageable pageable);

    long countByBand(String band);

    long countByStatus(String status);

    List<AlertEntity> findByIncidentId(String incidentId);
}
