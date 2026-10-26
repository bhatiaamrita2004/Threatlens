package com.threatlens.backend.service;

import com.threatlens.backend.domain.AlertEntity;
import com.threatlens.backend.domain.FeedbackEntity;
import com.threatlens.backend.domain.Verdict;
import com.threatlens.backend.dto.Api.AlertDetail;
import com.threatlens.backend.dto.Api.AlertIn;
import com.threatlens.backend.dto.Api.AlertView;
import com.threatlens.backend.dto.Api.EventView;
import com.threatlens.backend.dto.Api.FeedbackIn;
import com.threatlens.backend.dto.Api.FeedbackView;
import com.threatlens.backend.dto.Api.IngestAck;
import com.threatlens.backend.dto.PageResponse;
import com.threatlens.backend.error.NotFoundException;
import com.threatlens.backend.repository.AlertRepository;
import com.threatlens.backend.repository.EventRepository;
import com.threatlens.backend.repository.FeedbackRepository;
import com.threatlens.backend.search.EventSearchIndex;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class AlertService {

    private final AlertRepository alerts;
    private final EventRepository events;
    private final FeedbackRepository feedback;
    private final EventSearchIndex search;

    public AlertService(AlertRepository alerts, EventRepository events, FeedbackRepository feedback,
                        EventSearchIndex search) {
        this.search = search;
        this.alerts = alerts;
        this.events = events;
        this.feedback = feedback;
    }

    /**
     * Stores an alert from the detection pipeline. If the alertId already exists, the stored
     * alert is kept as it is and created=false is returned, so re-publishing is safe.
     */
    @Transactional
    public IngestAck ingest(AlertIn in) {
        if (alerts.existsById(in.alertId())) {
            return new IngestAck(in.alertId(), false);
        }
        AlertEntity a = new AlertEntity();
        a.setAlertId(in.alertId());
        a.setRuleName(in.ruleName());
        a.setSeverity(in.severity());
        a.setScore(in.score());
        a.setBand(in.band());
        a.setReason(in.reason());
        a.setExplanation(in.explanation());
        a.setUserId(in.userId());
        a.setSourceIp(in.sourceIp());
        a.setOccurredAt(in.occurredAt());
        a.setStatus("OPEN");
        a.setIncidentId(in.incidentId());
        a.getEvidenceEventIds().addAll(in.evidenceEventIds());
        alerts.save(a);
        search.applySeverity(in.evidenceEventIds(), in.band());
        return new IngestAck(in.alertId(), true);
    }

    @Transactional(readOnly = true)
    public PageResponse<AlertView> list(String band, String status, Pageable pageable) {
        var page = (band != null && status != null) ? alerts.findByBandAndStatus(band, status, pageable)
                : band != null ? alerts.findByBand(band, pageable)
                : status != null ? alerts.findByStatus(status, pageable)
                : alerts.findAll(pageable);
        return PageResponse.from(page.map(AlertService::toView));
    }

    /** The alert, the events that support it, and the analyst's feedback history. */
    @Transactional(readOnly = true)
    public AlertDetail detail(String alertId) {
        AlertEntity a = alerts.findById(alertId)
                .orElseThrow(() -> new NotFoundException("alert not found: " + alertId));
        List<EventView> evidence = events.findAllById(a.getEvidenceEventIds()).stream()
                .map(EventService::toView)
                .sorted(java.util.Comparator.comparing(EventView::occurredAt))
                .toList();
        List<FeedbackView> history = feedback.findByAlertIdOrderByCreatedAtAsc(alertId).stream()
                .map(AlertService::toFeedbackView)
                .toList();
        return new AlertDetail(toView(a), evidence, history);
    }

    /**
     * Records an analyst's verdict and moves the alert to a matching status:
     * TRUE_POSITIVE -> CONFIRMED, FALSE_POSITIVE -> DISMISSED, NEEDS_REVIEW -> IN_REVIEW.
     * Feedback is appended, never overwritten, so the history stays complete.
     */
    @Transactional
    public FeedbackView addFeedback(String alertId, FeedbackIn in, String analyst) {
        AlertEntity a = alerts.findById(alertId)
                .orElseThrow(() -> new NotFoundException("alert not found: " + alertId));

        FeedbackEntity f = new FeedbackEntity();
        f.setAlertId(alertId);
        f.setAnalyst(analyst);
        f.setVerdict(in.verdict());
        f.setNote(in.note());
        f.setCreatedAt(Instant.now());
        feedback.save(f);

        a.setStatus(statusFor(in.verdict()));
        alerts.save(a);
        return toFeedbackView(f);
    }

    static String statusFor(Verdict verdict) {
        return switch (verdict) {
            case TRUE_POSITIVE -> "CONFIRMED";
            case FALSE_POSITIVE -> "DISMISSED";
            case NEEDS_REVIEW -> "IN_REVIEW";
        };
    }

    // ---- mapping ----------------------------------------------------------

    static AlertView toView(AlertEntity a) {
        return new AlertView(a.getAlertId(), a.getRuleName(), a.getSeverity(), a.getScore(), a.getBand(),
                a.getReason(), a.getExplanation(), a.getUserId(), a.getSourceIp(), a.getOccurredAt(),
                a.getStatus(), a.getIncidentId());
    }

    static FeedbackView toFeedbackView(FeedbackEntity f) {
        return new FeedbackView(f.getId(), f.getAlertId(), f.getAnalyst(), f.getVerdict(), f.getNote(),
                f.getCreatedAt());
    }
}