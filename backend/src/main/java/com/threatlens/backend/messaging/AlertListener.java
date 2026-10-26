package com.threatlens.backend.messaging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatlens.backend.dto.Api.AlertIn;
import com.threatlens.backend.service.AlertService;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.Set;

/** Reads alerts from the threat-alerts topic and stores them. */
@Component
@ConditionalOnProperty(name = "threatlens.kafka.enabled", havingValue = "true", matchIfMissing = true)
public class AlertListener {

    private final ObjectMapper json;
    private final Validator validator;
    private final AlertService alerts;

    public AlertListener(ObjectMapper json, Validator validator, AlertService alerts) {
        this.json = json;
        this.validator = validator;
        this.alerts = alerts;
    }

    @KafkaListener(topics = "${threatlens.kafka.alerts-topic:threat-alerts}", groupId = "threatlens-backend")
    public void onAlert(String payload) throws JsonProcessingException {
        AlertIn in = json.readValue(payload, AlertIn.class);
        Set<ConstraintViolation<AlertIn>> problems = validator.validate(in);
        if (!problems.isEmpty()) {
            throw new IllegalArgumentException("invalid alert " + in.alertId() + ": " + problems);
        }
        alerts.ingest(in);
    }
}
