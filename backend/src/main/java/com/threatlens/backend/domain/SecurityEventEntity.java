package com.threatlens.backend.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/** One stored security event (the Phase 1 schema, as a table). */
@Entity
@Table(name = "security_events")
@Getter
@Setter
@NoArgsConstructor
public class SecurityEventEntity {

    @Id
    @Column(length = 64)
    private String eventId;

    @Column(nullable = false, length = 64)
    private String userId;

    @Column(nullable = false, length = 64)
    private String sourceIp;

    @Column(nullable = false, length = 32)
    private String eventType;

    @Column(nullable = false, length = 16)
    private String status;

    @Column(nullable = false)
    private Instant occurredAt;

    @Column(length = 64)
    private String location;

    private Integer destinationPort;

    @Column(length = 64)
    private String scenario;
}
