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

/** A group of related alerts (Phase 6), with a summary of who and where. */
@Entity
@Table(name = "incidents")
@Getter
@Setter
@NoArgsConstructor
public class IncidentEntity {

    @Id
    @Column(length = 100)
    private String incidentId;

    @Column(nullable = false)
    private int maxScore;

    @Column(nullable = false, length = 16)
    private String band;

    @Column(nullable = false)
    private Instant firstSeen;

    @Column(nullable = false)
    private Instant lastSeen;

    @Column(nullable = false)
    private int windowCount;

    @Column(length = 2000)
    private String explanation;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "incident_users", joinColumns = @JoinColumn(name = "incident_id"))
    @Column(name = "user_id", length = 64)
    private Set<String> users = new LinkedHashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "incident_source_ips", joinColumns = @JoinColumn(name = "incident_id"))
    @Column(name = "source_ip", length = 64)
    private Set<String> sourceIps = new LinkedHashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "incident_rules", joinColumns = @JoinColumn(name = "incident_id"))
    @Column(name = "rule_name", length = 64)
    private Set<String> rules = new LinkedHashSet<>();
}
