package com.threatlens.backend.repository;

import com.threatlens.backend.domain.IncidentEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IncidentRepository extends JpaRepository<IncidentEntity, String> {
}
