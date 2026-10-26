package com.threatlens.backend.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/** An analyst's verdict on an alert. Kept as a history, so nothing is overwritten. */
@Entity
@Table(name = "analyst_feedback")
@Getter
@Setter
@NoArgsConstructor
public class FeedbackEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String alertId;

    @Column(nullable = false, length = 64)
    private String analyst;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private Verdict verdict;

    @Column(length = 1000)
    private String note;

    @Column(nullable = false)
    private Instant createdAt;
}
