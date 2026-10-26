package com.threatlens.backend.repository;

import com.threatlens.backend.domain.FeedbackEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FeedbackRepository extends JpaRepository<FeedbackEntity, Long> {

    List<FeedbackEntity> findByAlertIdOrderByCreatedAtAsc(String alertId);
}
