package com.threatlens.backend.search;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatlens.backend.domain.SecurityEventEntity;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Event search on OpenSearch, called over its REST API. Indexing and search problems are logged
 * rather than thrown, so a search outage never stops events being stored in Postgres.
 */
@Component
@ConditionalOnProperty(name = "threatlens.opensearch.enabled", havingValue = "true")
public class OpenSearchEventIndex implements EventSearchIndex {

    private static final Logger log = LoggerFactory.getLogger(OpenSearchEventIndex.class);
    private static final MediaType NDJSON = MediaType.parseMediaType("application/x-ndjson");
    private static final Map<String, Integer> RANK = Map.of("LOW", 1, "MEDIUM", 2, "HIGH", 3, "CRITICAL", 4);
    private static final String MAPPING = """
            {"mappings":{"properties":{
              "eventId":{"type":"keyword"},
              "userId":{"type":"keyword"},
              "sourceIp":{"type":"ip"},
              "eventType":{"type":"keyword"},
              "status":{"type":"keyword"},
              "occurredAt":{"type":"date"},
              "location":{"type":"keyword"},
              "destinationPort":{"type":"integer"},
              "scenario":{"type":"keyword"},
              "severity":{"type":"keyword"},
              "severityRank":{"type":"integer"}
            }}}
            """;

    private final RestClient client;
    private final ObjectMapper json;
    private final String index;

    public OpenSearchEventIndex(RestClient.Builder builder, ObjectMapper json,
                                @Value("${threatlens.opensearch.url}") String url,
                                @Value("${threatlens.opensearch.index:threatlens-events}") String index) {
        this.client = builder.baseUrl(url).build();
        this.json = json;
        this.index = index;
    }

    /** Creates the index with its field types if it does not exist yet. */
    @PostConstruct
    void ensureIndex() {
        try {
            client.head().uri("/{index}", index).retrieve().toBodilessEntity();
        } catch (HttpClientErrorException.NotFound e) {
            client.put().uri("/{index}", index)
                    .contentType(MediaType.APPLICATION_JSON).body(MAPPING)
                    .retrieve().toBodilessEntity();
            log.info("created OpenSearch index {}", index);
        } catch (RuntimeException e) {
            log.warn("OpenSearch not reachable at startup: {}", e.getMessage());
        }
    }

    @Override
    public void indexEvents(List<SecurityEventEntity> events) {
        if (events.isEmpty()) {
            return;
        }
        StringBuilder body = new StringBuilder();
        for (SecurityEventEntity e : events) {
            Map<String, Object> doc = new HashMap<>();
            doc.put("eventId", e.getEventId());
            doc.put("userId", e.getUserId());
            doc.put("sourceIp", e.getSourceIp());
            doc.put("eventType", e.getEventType());
            doc.put("status", e.getStatus());
            doc.put("occurredAt", e.getOccurredAt().toString());
            doc.put("location", e.getLocation());
            doc.put("destinationPort", e.getDestinationPort());
            doc.put("scenario", e.getScenario());
            doc.put("severity", "NONE");
            doc.put("severityRank", 0);
            body.append(line(Map.of("index", Map.of("_index", index, "_id", e.getEventId())))).append('\n');
            body.append(line(doc)).append('\n');
        }
        send(body);
    }

    @Override
    public void applySeverity(Collection<String> eventIds, String band) {
        if (eventIds.isEmpty()) {
            return;
        }
        int rank = RANK.getOrDefault(band, 0);
        // Only raise the severity, never lower it: an event keeps its worst alert band.
        String script = "if (ctx._source.severityRank == null || params.rank > ctx._source.severityRank) "
                + "{ ctx._source.severity = params.band; ctx._source.severityRank = params.rank; }";
        StringBuilder body = new StringBuilder();
        for (String id : eventIds) {
            body.append(line(Map.of("update", Map.of("_index", index, "_id", id)))).append('\n');
            body.append(line(Map.of("script", Map.of(
                    "source", script,
                    "params", Map.of("band", band, "rank", rank))))).append('\n');
        }
        send(body);
    }

    @Override
    public Page search(Criteria c, int page, int size) {
        List<Object> filters = new ArrayList<>();
        if (c.sourceIp() != null) {
            filters.add(Map.of("term", Map.of("sourceIp", c.sourceIp())));
        }
        if (c.eventType() != null) {
            filters.add(Map.of("term", Map.of("eventType", c.eventType())));
        }
        if (c.severity() != null) {
            filters.add(Map.of("range", Map.of("severityRank",
                    Map.of("gte", RANK.getOrDefault(c.severity(), 1)))));
        }
        Map<String, Object> time = new LinkedHashMap<>();
        if (c.from() != null) {
            time.put("gte", c.from().toString());
        }
        if (c.to() != null) {
            time.put("lte", c.to().toString());
        }
        if (!time.isEmpty()) {
            filters.add(Map.of("range", Map.of("occurredAt", time)));
        }

        Map<String, Object> query = Map.of(
                "query", Map.of("bool", Map.of("filter", filters)),
                "sort", List.of(Map.of("occurredAt", "desc")),
                "from", page * size,
                "size", size,
                "track_total_hits", true);
        try {
            JsonNode reply = client.post().uri("/{index}/_search", index)
                    .contentType(MediaType.APPLICATION_JSON).body(query)
                    .retrieve().body(JsonNode.class);
            long total = reply.path("hits").path("total").path("value").asLong(0);
            List<Map<String, Object>> items = new ArrayList<>();
            for (JsonNode hit : reply.path("hits").path("hits")) {
                items.add(json.convertValue(hit.get("_source"), new TypeReference<Map<String, Object>>() {
                }));
            }
            return new Page(total, items);
        } catch (RestClientException e) {
            throw new IllegalStateException("search failed: " + e.getMessage(), e);
        }
    }

    // ---- helpers ----------------------------------------------------------

    private String line(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Sends newline-delimited bulk actions. Failures are logged; Postgres already has the data. */
    private void send(StringBuilder body) {
        try {
            Map<?, ?> reply = client.post().uri("/_bulk")
                    .contentType(NDJSON).body(body.toString())
                    .retrieve().body(Map.class);
            if (reply != null && Boolean.TRUE.equals(reply.get("errors"))) {
                log.warn("some OpenSearch bulk items failed (events not indexed yet, or index problem)");
            }
        } catch (RuntimeException e) {
            log.warn("OpenSearch bulk call failed: {}", e.getMessage());
        }
    }
}