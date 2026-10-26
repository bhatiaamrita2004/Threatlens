package com.threatlens.backend;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The health endpoint is public (no token) and reports only the overall status, so a load
 * balancer or a container platform can check the app without credentials.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:healthtest;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=validate",
        "threatlens.seed-demo-users=true",
        "threatlens.kafka.enabled=false",
        "threatlens.redis.enabled=false",
        "threatlens.opensearch.enabled=false",
        // Redis is not running in tests, so its health check would report DOWN.
        "management.health.redis.enabled=false"
})
@AutoConfigureMockMvc
class HealthEndpointTests {

    @Autowired
    private MockMvc mvc;

    @Test
    void healthIsPublicAndReportsUp() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}