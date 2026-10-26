package com.threatlens.backend.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

/** An alert from the detection pipeline, with the events that support it. */
@Entity
@Table(name = "alerts")
@Getter
@Setter
@NoArgsConstructor
public class AlertEntity {

    @Id
    @Column(length = 100)
    private String alertId;

    @Column(nullable = false, length = 64)
    private String ruleName;

    @Column(nullable = false, length = 16)
    private String severity;

    @Column(nullable = false)
    private int score;

    @Column(nullable = false, length = 16)
    private String band;

    @Column(nullable = false, length = 512)
    private String reason;

    @Column(length = 2000)
    private String explanation;

    @Column(length = 64)
    private String userId;

    @Column(length = 64)
    private String sourceIp;

    @Column(nullable = false)
    private Instant occurredAt;

    /** OPEN, CONFIRMED, DISMISSED or IN_REVIEW. Changed by analyst feedback. */
    @Column(nullable = false, length = 16)
    private String status = "OPEN";

    @Column(length = 100)
    private String incidentId;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "alert_evidence", joinColumns = @JoinColumn(name = "alert_id"))
    @Column(name = "event_id", length = 64)
    private Set<String> evidenceEventIds = new LinkedHashSet<>();
}
