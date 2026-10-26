package com.threatlens.backend.search;

import com.threatlens.backend.domain.SecurityEventEntity;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

/** Used when OpenSearch is turned off (for example in tests). Nothing is indexed. */
@Component
@ConditionalOnProperty(name = "threatlens.opensearch.enabled", havingValue = "false")
public class NoOpEventSearchIndex implements EventSearchIndex {

    @Override
    public void indexEvents(List<SecurityEventEntity> events) {
    }

    @Override
    public void applySeverity(Collection<String> eventIds, String band) {
    }

    @Override
    public Page search(Criteria criteria, int page, int size) {
        return new Page(0, List.of());
    }
}