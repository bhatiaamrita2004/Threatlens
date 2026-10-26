package com.threatlens.backend.controller;

import com.threatlens.backend.dto.Api.EventBatch;
import com.threatlens.backend.dto.Api.EventView;
import com.threatlens.backend.dto.Api.IngestResult;
import com.threatlens.backend.dto.PageResponse;
import com.threatlens.backend.service.EventService;
import jakarta.validation.Valid;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/events")
public class EventController {

    private final EventService events;

    public EventController(EventService events) {
        this.events = events;
    }

    /** Admin only. Accepts up to 1000 events per call. Duplicate eventIds are skipped. */
    @PostMapping
    public IngestResult ingest(@Valid @RequestBody EventBatch batch) {
        return events.ingest(batch);
    }

    @GetMapping
    public PageResponse<EventView> list(
            @RequestParam(required = false) String userId,
            @ParameterObject @PageableDefault(size = 20, sort = "occurredAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return events.list(userId, pageable);
    }

    @GetMapping("/{eventId}")
    public EventView get(@PathVariable String eventId) {
        return events.get(eventId);
    }
}
