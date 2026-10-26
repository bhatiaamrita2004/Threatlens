package com.threatlens.backend.dto;

import com.threatlens.backend.domain.Verdict;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Request and response shapes for the API. Each record is what goes over the wire,
 * so the entities are never exposed directly.
 */
public final class Api {

    private Api() {
    }

    // ---- auth -------------------------------------------------------------

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {
    }

    public record LoginResponse(String token, String username, String role, long expiresInSeconds) {
    }

    // ---- events -----------------------------------------------------------

    public record EventIn(
            @NotBlank @Size(max = 64) String eventId,
            @NotBlank @Size(max = 64) String userId,
            @NotBlank @Size(max = 64) String sourceIp,
            @NotBlank @Pattern(regexp = "LOGIN_SUCCESS|LOGIN_FAILED|CONNECTION_ATTEMPT|API_REQUEST|PRIVILEGE_CHANGE|RESOURCE_ACCESS") String eventType,
            @NotBlank @Pattern(regexp = "SUCCESS|FAILURE|INFO") String status,
            @NotNull Instant occurredAt,
            @Size(max = 64) String location,
            @Min(0) @Max(65535) Integer destinationPort,
            @Size(max = 64) String scenario) {
    }

    public record EventBatch(@NotEmpty @Size(max = 1000) List<@Valid EventIn> events) {
    }

    public record IngestResult(int received, int inserted, int skipped) {
    }

    public record EventView(String eventId, String userId, String sourceIp, String eventType, String status,
                            Instant occurredAt, String location, Integer destinationPort, String scenario) {
    }

    // ---- alerts -----------------------------------------------------------

    public record AlertIn(
            @NotBlank @Size(max = 100) String alertId,
            @NotBlank @Size(max = 64) String ruleName,
            @NotBlank @Pattern(regexp = "LOW|MEDIUM|HIGH|CRITICAL") String severity,
            @Min(0) @Max(100) int score,
            @NotBlank @Pattern(regexp = "LOW|MEDIUM|HIGH|CRITICAL") String band,
            @NotBlank @Size(max = 512) String reason,
            @Size(max = 2000) String explanation,
            @Size(max = 64) String userId,
            @Size(max = 64) String sourceIp,
            @NotNull Instant occurredAt,
            @NotEmpty List<@NotBlank @Size(max = 64) String> evidenceEventIds,
            @Size(max = 100) String incidentId) {
    }

    public record AlertView(String alertId, String ruleName, String severity, int score, String band,
                            String reason, String explanation, String userId, String sourceIp,
                            Instant occurredAt, String status, String incidentId) {
    }

    public record FeedbackIn(@NotNull Verdict verdict, @Size(max = 1000) String note) {
    }

    public record FeedbackView(Long id, String alertId, String analyst, Verdict verdict, String note,
                               Instant createdAt) {
    }

    public record AlertDetail(AlertView alert, List<EventView> evidenceEvents, List<FeedbackView> feedback) {
    }

    // ---- incidents --------------------------------------------------------

    public record IncidentIn(
            @NotBlank @Size(max = 100) String incidentId,
            @Min(0) @Max(100) int maxScore,
            @NotBlank @Pattern(regexp = "LOW|MEDIUM|HIGH|CRITICAL") String band,
            @NotNull Instant firstSeen,
            @NotNull Instant lastSeen,
            @Min(1) int windowCount,
            @Size(max = 2000) String explanation,
            List<@Size(max = 64) String> users,
            List<@Size(max = 64) String> sourceIps,
            List<@Size(max = 64) String> rules) {
    }

    public record IncidentView(String incidentId, int maxScore, String band, Instant firstSeen, Instant lastSeen,
                               int windowCount, String explanation, List<String> users,
                               List<String> sourceIps, List<String> rules) {
    }

    public record IncidentDetail(IncidentView incident, List<AlertView> alerts) {
    }

    // ---- shared -----------------------------------------------------------

    /** Result of an ingest call. created=false means the item already existed. */
    public record IngestAck(String id, boolean created) {
    }

    public record DashboardSummary(long totalEvents, long totalAlerts, long openAlerts, long totalIncidents,
                                   Map<String, Long> alertsByBand, List<IncidentView> topIncidents) {
    }
}
