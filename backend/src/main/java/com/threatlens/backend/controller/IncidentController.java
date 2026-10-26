package com.threatlens.backend.controller;

import com.threatlens.backend.dto.Api.IncidentDetail;
import com.threatlens.backend.dto.Api.IncidentIn;
import com.threatlens.backend.dto.Api.IncidentView;
import com.threatlens.backend.dto.Api.IngestAck;
import com.threatlens.backend.dto.PageResponse;
import com.threatlens.backend.service.IncidentService;
import jakarta.validation.Valid;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {

    private final IncidentService incidents;

    public IncidentController(IncidentService incidents) {
        this.incidents = incidents;
    }

    /** Admin only. Creates the incident (201) or updates it in place (200). */
    @PostMapping
    public ResponseEntity<IngestAck> upsert(@Valid @RequestBody IncidentIn in) {
        IngestAck ack = incidents.upsert(in);
        return ResponseEntity.status(ack.created() ? HttpStatus.CREATED : HttpStatus.OK).body(ack);
    }

    @GetMapping
    public PageResponse<IncidentView> list(
            @ParameterObject @PageableDefault(size = 20, sort = "maxScore", direction = Sort.Direction.DESC) Pageable pageable) {
        return incidents.list(pageable);
    }

    @GetMapping("/{incidentId}")
    public IncidentDetail detail(@PathVariable String incidentId) {
        return incidents.detail(incidentId);
    }
}
