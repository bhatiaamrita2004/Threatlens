package com.threatlens.backend.messaging;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.TopicPartition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.util.backoff.FixedBackOff;

/**
 * Topics and error handling.
 * A failing message is retried 3 times, 1 second apart. If it still fails, or it is
 * malformed, it is sent to a "dead letter" topic (name ends in .DLT) so nothing is lost silently.
 */
@Configuration
@ConditionalOnProperty(name = "threatlens.kafka.enabled", havingValue = "true", matchIfMissing = true)
public class KafkaConfig {

    @Bean
    public NewTopic securityEventsTopic() {
        return TopicBuilder.name("security-events").partitions(3).replicas(1).build();
    }

    @Bean
    public NewTopic threatAlertsTopic() {
        return TopicBuilder.name("threat-alerts").partitions(3).replicas(1).build();
    }

    @Bean
    public NewTopic securityEventsDlt() {
        return TopicBuilder.name("security-events.DLT").partitions(1).replicas(1).build();
    }

    @Bean
    public NewTopic threatAlertsDlt() {
        return TopicBuilder.name("threat-alerts.DLT").partitions(1).replicas(1).build();
    }

    @Bean
    public DefaultErrorHandler kafkaErrorHandler(KafkaTemplate<?, ?> template) {
        DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(
                template, (record, ex) -> new TopicPartition(record.topic() + ".DLT", -1));
        DefaultErrorHandler handler = new DefaultErrorHandler(recoverer, new FixedBackOff(1000L, 3L));
        // Retrying cannot fix bad JSON or invalid data, so send these straight to the dead letter topic.
        handler.addNotRetryableExceptions(IllegalArgumentException.class, JsonProcessingException.class);
        return handler;
    }
}
