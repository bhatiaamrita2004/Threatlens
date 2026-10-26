package com.threatlens.backend.controller;

import com.threatlens.backend.dto.Api.AlertDetail;
import com.threatlens.backend.dto.Api.AlertIn;
import com.threatlens.backend.dto.Api.AlertView;
import com.threatlens.backend.dto.Api.FeedbackIn;
import com.threatlens.backend.dto.Api.FeedbackView;
import com.threatlens.backend.dto.Api.IngestAck;
import com.threatlens.backend.dto.PageResponse;
import com.threatlens.backend.service.AlertService;
import jakarta.validation.Valid;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService alerts;

    public AlertController(AlertService alerts) {
        this.alerts = alerts;
    }

    /** Admin only. 201 when stored, 200 when the alert already existed. */
    @PostMapping
    public ResponseEntity<IngestAck> ingest(@Valid @RequestBody AlertIn in) {
        IngestAck ack = alerts.ingest(in);
        return ResponseEntity.status(ack.created() ? HttpStatus.CREATED : HttpStatus.OK).body(ack);
    }

    @GetMapping
    public PageResponse<AlertView> list(
            @RequestParam(required = false) String band,
            @RequestParam(required = false) String status,
            @ParameterObject @PageableDefault(size = 20, sort = "occurredAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return alerts.list(band, status, pageable);
    }

    @GetMapping("/{alertId}")
    public AlertDetail detail(@PathVariable String alertId) {
        return alerts.detail(alertId);
    }

    /** Analyst or admin. The analyst name comes from the token. */
    @PostMapping("/{alertId}/feedback")
    public ResponseEntity<FeedbackView> feedback(@PathVariable String alertId,
                                                 @Valid @RequestBody FeedbackIn in,
                                                 Authentication auth) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(alerts.addFeedback(alertId, in, auth.getName()));
    }
}
