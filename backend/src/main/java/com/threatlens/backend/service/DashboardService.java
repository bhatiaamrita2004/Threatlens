package com.threatlens.backend.service;

import com.threatlens.backend.dto.Api.DashboardSummary;
import com.threatlens.backend.dto.Api.IncidentView;
import com.threatlens.backend.repository.AlertRepository;
import com.threatlens.backend.repository.EventRepository;
import com.threatlens.backend.repository.IncidentRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Counts and top incidents for the dashboard home page. */
@Service
public class DashboardService {

    private static final List<String> BANDS = List.of("LOW", "MEDIUM", "HIGH", "CRITICAL");

    private final EventRepository events;
    private final AlertRepository alerts;
    private final IncidentRepository incidents;

    public DashboardService(EventRepository events, AlertRepository alerts, IncidentRepository incidents) {
        this.events = events;
        this.alerts = alerts;
        this.incidents = incidents;
    }

    @Transactional(readOnly = true)
    public DashboardSummary summary() {
        Map<String, Long> byBand = new LinkedHashMap<>();
        for (String band : BANDS) {
            byBand.put(band, alerts.countByBand(band));
        }
        List<IncidentView> top = incidents
                .findAll(PageRequest.of(0, 5, Sort.by(Sort.Direction.DESC, "maxScore")))
                .map(IncidentService::toView)
                .getContent();

        return new DashboardSummary(
                events.count(),
                alerts.count(),
                alerts.countByStatus("OPEN"),
                incidents.count(),
                byBand,
                top);
    }
}
