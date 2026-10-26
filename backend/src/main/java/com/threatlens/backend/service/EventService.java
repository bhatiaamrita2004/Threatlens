package com.threatlens.backend.service;

import com.threatlens.backend.domain.SecurityEventEntity;
import com.threatlens.backend.dto.Api.EventBatch;
import com.threatlens.backend.dto.Api.EventIn;
import com.threatlens.backend.dto.Api.EventView;
import com.threatlens.backend.dto.Api.IngestResult;
import com.threatlens.backend.dto.PageResponse;
import com.threatlens.backend.repository.EventRepository;
import com.threatlens.backend.search.EventSearchIndex;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class EventService {

    private final EventRepository events;
    private final EventSearchIndex search;

    public EventService(EventRepository events, EventSearchIndex search) {
        this.events = events;
        this.search = search;
    }

    /**
     * Stores a batch of events. An event whose eventId already exists (or appears twice in the
     * batch) is skipped, so sending the same batch again is safe.
     */
    @Transactional
    public IngestResult ingest(EventBatch batch) {
        List<EventIn> incoming = batch.events();
        Set<String> ids = incoming.stream().map(EventIn::eventId).collect(Collectors.toSet());
        Set<String> existing = events.findAllById(ids).stream()
                .map(SecurityEventEntity::getEventId)
                .collect(Collectors.toSet());

        Set<String> seenInBatch = new HashSet<>();
        List<SecurityEventEntity> toSave = new ArrayList<>();
        for (EventIn in : incoming) {
            if (existing.contains(in.eventId()) || !seenInBatch.add(in.eventId())) {
                continue;
            }
            toSave.add(toEntity(in));
        }
        events.saveAll(toSave);
        search.indexEvents(toSave);
        return new IngestResult(incoming.size(), toSave.size(), incoming.size() - toSave.size());
    }

    @Transactional(readOnly = true)
    public PageResponse<EventView> list(String userId, Pageable pageable) {
        var page = (userId == null || userId.isBlank())
                ? events.findAll(pageable)
                : events.findByUserId(userId, pageable);
        return PageResponse.from(page.map(EventService::toView));
    }

    @Transactional(readOnly = true)
    public EventView get(String eventId) {
        return events.findById(eventId)
                .map(EventService::toView)
                .orElseThrow(() -> new com.threatlens.backend.error.NotFoundException(
                        "event not found: " + eventId));
    }

    // ---- mapping ----------------------------------------------------------

    static SecurityEventEntity toEntity(EventIn in) {
        SecurityEventEntity e = new SecurityEventEntity();
        e.setEventId(in.eventId());
        e.setUserId(in.userId());
        e.setSourceIp(in.sourceIp());
        e.setEventType(in.eventType());
        e.setStatus(in.status());
        e.setOccurredAt(in.occurredAt());
        e.setLocation(in.location());
        e.setDestinationPort(in.destinationPort());
        e.setScenario(in.scenario());
        return e;
    }

    static EventView toView(SecurityEventEntity e) {
        return new EventView(e.getEventId(), e.getUserId(), e.getSourceIp(), e.getEventType(),
                e.getStatus(), e.getOccurredAt(), e.getLocation(), e.getDestinationPort(), e.getScenario());
    }
}