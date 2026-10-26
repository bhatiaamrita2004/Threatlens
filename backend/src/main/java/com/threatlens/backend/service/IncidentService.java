package com.threatlens.backend.service;

import com.threatlens.backend.domain.IncidentEntity;
import com.threatlens.backend.dto.Api.AlertDetail;
import com.threatlens.backend.dto.Api.AlertView;
import com.threatlens.backend.dto.Api.IncidentDetail;
import com.threatlens.backend.dto.Api.IncidentIn;
import com.threatlens.backend.dto.Api.IncidentView;
import com.threatlens.backend.dto.Api.IngestAck;
import com.threatlens.backend.dto.PageResponse;
import com.threatlens.backend.error.NotFoundException;
import com.threatlens.backend.repository.AlertRepository;
import com.threatlens.backend.repository.IncidentRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class IncidentService {

    private final IncidentRepository incidents;
    private final AlertRepository alerts;

    public IncidentService(IncidentRepository incidents, AlertRepository alerts) {
        this.incidents = incidents;
        this.alerts = alerts;
    }

    /**
     * Stores or updates an incident. Incidents grow as new alerts arrive, so an existing
     * incident is updated in place (created=false), not rejected.
     */
    @Transactional
    public IngestAck upsert(IncidentIn in) {
        boolean created = !incidents.existsById(in.incidentId());
        IncidentEntity i = created ? new IncidentEntity()
                : incidents.findById(in.incidentId()).orElseThrow();
        i.setIncidentId(in.incidentId());
        i.setMaxScore(in.maxScore());
        i.setBand(in.band());
        i.setFirstSeen(in.firstSeen());
        i.setLastSeen(in.lastSeen());
        i.setWindowCount(in.windowCount());
        i.setExplanation(in.explanation());
        i.setUsers(new java.util.LinkedHashSet<>(orEmpty(in.users())));
        i.setSourceIps(new java.util.LinkedHashSet<>(orEmpty(in.sourceIps())));
        i.setRules(new java.util.LinkedHashSet<>(orEmpty(in.rules())));
        incidents.save(i);
        return new IngestAck(in.incidentId(), created);
    }

    @Transactional(readOnly = true)
    public PageResponse<IncidentView> list(Pageable pageable) {
        return PageResponse.from(incidents.findAll(pageable).map(IncidentService::toView));
    }

    @Transactional(readOnly = true)
    public IncidentDetail detail(String incidentId) {
        IncidentEntity i = incidents.findById(incidentId)
                .orElseThrow(() -> new NotFoundException("incident not found: " + incidentId));
        List<AlertView> linked = alerts.findByIncidentId(incidentId).stream()
                .map(AlertService::toView)
                .toList();
        return new IncidentDetail(toView(i), linked);
    }

    static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }

    static IncidentView toView(IncidentEntity i) {
        return new IncidentView(i.getIncidentId(), i.getMaxScore(), i.getBand(), i.getFirstSeen(),
                i.getLastSeen(), i.getWindowCount(), i.getExplanation(),
                List.copyOf(i.getUsers()), List.copyOf(i.getSourceIps()), List.copyOf(i.getRules()));
    }
}
