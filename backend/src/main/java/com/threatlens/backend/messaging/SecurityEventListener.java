package com.threatlens.backend.messaging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatlens.backend.dto.Api.EventBatch;
import com.threatlens.backend.dto.Api.EventIn;
import com.threatlens.backend.service.EventService;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/** Reads one security event per message from the security-events topic and stores it. */
@Component
@ConditionalOnProperty(name = "threatlens.kafka.enabled", havingValue = "true", matchIfMissing = true)
public class SecurityEventListener {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventListener.class);

    private final ObjectMapper json;
    private final Validator validator;
    private final EventService events;

    public SecurityEventListener(ObjectMapper json, Validator validator, EventService events) {
        this.json = json;
        this.validator = validator;
        this.events = events;
    }

    @KafkaListener(topics = "${threatlens.kafka.events-topic:security-events}", groupId = "threatlens-backend")
    public void onEvent(String payload) throws JsonProcessingException {
        EventIn in = json.readValue(payload, EventIn.class);
        Set<ConstraintViolation<EventIn>> problems = validator.validate(in);
        if (!problems.isEmpty()) {
            throw new IllegalArgumentException("invalid event " + in.eventId() + ": " + problems);
        }
        // EventService skips an eventId it already has, so a redelivered message is harmless.
        var result = events.ingest(new EventBatch(List.of(in)));
        log.info("event {} stored={}", in.eventId(), result.inserted() == 1);
    }
}
