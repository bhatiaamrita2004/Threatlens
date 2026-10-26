package com.threatlens.backend.service;
   import java.util.stream.StreamSupport;
import com.threatlens.backend.domain.SecurityEventEntity;
import com.threatlens.backend.dto.Api.EventBatch;
import com.threatlens.backend.dto.Api.EventIn;
import com.threatlens.backend.dto.Api.IngestResult;
import com.threatlens.backend.repository.EventRepository;
import com.threatlens.backend.search.EventSearchIndex;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for event ingest: duplicates must be skipped and only new events indexed. */
class EventServiceTest {

    private final EventRepository events = mock(EventRepository.class);
    private final EventSearchIndex search = mock(EventSearchIndex.class);
    private final EventService service = new EventService(events, search);

    private static EventIn event(String id) {
        return new EventIn(id, "U1", "10.0.0.1", "LOGIN_FAILED", "FAILURE",
                Instant.parse("2026-06-01T10:00:00Z"), "London", 22, "test");
    }

    @Test
    void duplicatesInDatabaseAndWithinBatchAreSkipped() {
        SecurityEventEntity existing = new SecurityEventEntity();
        existing.setEventId("E1");
        when(events.findAllById(anyIterable())).thenReturn(List.of(existing));

        IngestResult result = service.ingest(new EventBatch(List.of(event("E1"), event("E2"), event("E2"))));

        assertThat(result).isEqualTo(new IngestResult(3, 1, 2));
        verify(search).indexEvents(argThat(saved ->
                saved.size() == 1 && saved.get(0).getEventId().equals("E2")));
    }

    @Test
    void newEventsAreSavedAndIndexed() {
        when(events.findAllById(anyIterable())).thenReturn(List.of());

        IngestResult result = service.ingest(new EventBatch(List.of(event("N1"), event("N2"))));

        assertThat(result).isEqualTo(new IngestResult(2, 2, 0));
                   verify(events).saveAll(argThat((Iterable<SecurityEventEntity> saved) ->
                   StreamSupport.stream(saved.spliterator(), false).count() == 2));
    }
}