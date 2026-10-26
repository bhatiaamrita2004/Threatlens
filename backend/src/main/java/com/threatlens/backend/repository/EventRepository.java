package com.threatlens.backend.repository;

import com.threatlens.backend.domain.SecurityEventEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EventRepository extends JpaRepository<SecurityEventEntity, String> {

    Page<SecurityEventEntity> findByUserId(String userId, Pageable pageable);
}
