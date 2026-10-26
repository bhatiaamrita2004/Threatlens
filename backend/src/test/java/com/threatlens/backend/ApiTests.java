package com.threatlens.backend;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end API tests against an in-memory H2 database. Each test runs through the real
 * security filters, so role rules are checked too.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:apitest;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=validate",
        "threatlens.seed-demo-users=true",
        "threatlens.kafka.enabled=false",
        "threatlens.redis.enabled=false",
        "threatlens.opensearch.enabled=false"
})
@AutoConfigureMockMvc
class ApiTests {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper json;

    // ---- helpers ----------------------------------------------------------

    private String login(String user, String password) throws Exception {
        String body = json.writeValueAsString(Map.of("username", user, "password", password));
        MvcResult r = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andReturn();
        return json.readTree(r.getResponse().getContentAsString()).get("token").asText();
    }

    private static String event(String id, String user, String ip, String type, String status, String time) {
        return """
                {"eventId":"%s","userId":"%s","sourceIp":"%s","eventType":"%s","status":"%s",
                 "occurredAt":"%s","location":"London","destinationPort":22,"scenario":"test"}
                """.formatted(id, user, ip, type, status, time);
    }

    private static String alert(String id, String incidentId) {
        return """
                {"alertId":"%s","ruleName":"REPEATED_FAILED_LOGIN","severity":"HIGH","score":75,
                 "band":"HIGH","reason":"12 failed logins","explanation":"test",
                 "userId":"U001","sourceIp":"203.0.113.9","occurredAt":"2026-06-01T10:00:00Z",
                 "evidenceEventIds":["E1","E2"],"incidentId":%s}
                """.formatted(id, incidentId == null ? "null" : "\"" + incidentId + "\"");
    }

    // ---- auth -------------------------------------------------------------

    @Test
    void loginWithGoodPasswordReturnsToken() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"analyst\",\"password\":\"analyst123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ANALYST"))
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    @Test
    void loginWithWrongPasswordIsUnauthorized() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"analyst\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("invalid username or password"));
    }

    @Test
    void readWithoutTokenIsUnauthorized() throws Exception {
        mvc.perform(get("/api/alerts")).andExpect(status().isUnauthorized());
    }

    @Test
    void analystCannotIngestButAdminCan() throws Exception {
        String analyst = login("analyst", "analyst123");
        mvc.perform(post("/api/events").header("Authorization", "Bearer " + analyst)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"events\":[" + event("A1", "U1", "10.0.0.1", "LOGIN_FAILED", "FAILURE",
                                "2026-06-01T10:00:00Z") + "]}"))
                .andExpect(status().isForbidden());

        String admin = login("admin", "admin123");
        mvc.perform(post("/api/events").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"events\":[" + event("A1", "U1", "10.0.0.1", "LOGIN_FAILED", "FAILURE",
                                "2026-06-01T10:00:00Z") + "]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.inserted").value(1));
    }

    // ---- events -----------------------------------------------------------

    @Test
    void duplicateEventsAreSkipped() throws Exception {
        String admin = login("admin", "admin123");
        String batch = "{\"events\":[" + event("D1", "U2", "10.0.0.2", "LOGIN_SUCCESS", "SUCCESS",
                "2026-06-01T11:00:00Z") + "," + event("D1", "U2", "10.0.0.2", "LOGIN_SUCCESS", "SUCCESS",
                "2026-06-01T11:00:00Z") + "]}";

        mvc.perform(post("/api/events").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON).content(batch))
                .andExpect(jsonPath("$.received").value(2))
                .andExpect(jsonPath("$.inserted").value(1))
                .andExpect(jsonPath("$.skipped").value(1));

        mvc.perform(post("/api/events").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON).content(batch))
                .andExpect(jsonPath("$.inserted").value(0))
                .andExpect(jsonPath("$.skipped").value(2));
    }

    @Test
    void invalidEventIsRejectedWithFieldErrors() throws Exception {
        String admin = login("admin", "admin123");
        String bad = "{\"events\":[{\"eventId\":\"X\",\"userId\":\"U\",\"sourceIp\":\"1.1.1.1\","
                + "\"eventType\":\"NOT_A_TYPE\",\"status\":\"SUCCESS\",\"occurredAt\":\"2026-06-01T10:00:00Z\"}]}";
        mvc.perform(post("/api/events").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON).content(bad))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors").exists());
    }

    @Test
    void eventsCanBeFilteredByUser() throws Exception {
        String admin = login("admin", "admin123");
        String analyst = login("analyst", "analyst123");
        String batch = "{\"events\":[" + event("F1", "FILTER_USER", "10.0.0.3", "API_REQUEST", "INFO",
                "2026-06-02T09:00:00Z") + "]}";
        mvc.perform(post("/api/events").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content(batch)).andExpect(status().isOk());

        mvc.perform(get("/api/events").param("userId", "FILTER_USER")
                        .header("Authorization", "Bearer " + analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[0].eventId").value("F1"));
    }

    // ---- alerts and feedback ----------------------------------------------

    @Test
    void alertIngestIsIdempotentAndDetailShowsEvidence() throws Exception {
        String admin = login("admin", "admin123");
        String analyst = login("analyst", "analyst123");

        mvc.perform(post("/api/alerts").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON).content(alert("ALERT-1", null)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.created").value(true));

        mvc.perform(post("/api/alerts").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON).content(alert("ALERT-1", null)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.created").value(false));

        mvc.perform(get("/api/alerts/ALERT-1").header("Authorization", "Bearer " + analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alert.status").value("OPEN"))
                .andExpect(jsonPath("$.feedback").isEmpty());
    }

    @Test
    void feedbackChangesStatusAndKeepsHistory() throws Exception {
        String admin = login("admin", "admin123");
        String analyst = login("analyst", "analyst123");

        mvc.perform(post("/api/alerts").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content(alert("ALERT-2", null)));

        mvc.perform(post("/api/alerts/ALERT-2/feedback").header("Authorization", "Bearer " + analyst)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verdict\":\"FALSE_POSITIVE\",\"note\":\"known scanner\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.analyst").value("analyst"))
                .andExpect(jsonPath("$.verdict").value("FALSE_POSITIVE"));

        mvc.perform(post("/api/alerts/ALERT-2/feedback").header("Authorization", "Bearer " + analyst)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"verdict\":\"NEEDS_REVIEW\"}"))
                .andExpect(status().isCreated());

        mvc.perform(get("/api/alerts/ALERT-2").header("Authorization", "Bearer " + analyst))
                .andExpect(jsonPath("$.alert.status").value("IN_REVIEW"))
                .andExpect(jsonPath("$.feedback.length()").value(2))
                .andExpect(jsonPath("$.feedback[0].note").value("known scanner"));
    }

    @Test
    void unknownAlertIsNotFoundAsProblemDocument() throws Exception {
        String analyst = login("analyst", "analyst123");
        mvc.perform(get("/api/alerts/NOPE").header("Authorization", "Bearer " + analyst))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.detail").value(containsString("NOPE")));
    }

    @Test
    void alertsCanBeFilteredByBand() throws Exception {
        String analyst = login("analyst", "analyst123");
        mvc.perform(get("/api/alerts").param("band", "HIGH")
                        .header("Authorization", "Bearer " + analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items").isArray());
    }

    // ---- incidents and dashboard ------------------------------------------

    @Test
    void incidentUpsertLinksAlertsAndDashboardCounts() throws Exception {
        String admin = login("admin", "admin123");
        String analyst = login("analyst", "analyst123");

        String incident = """
                {"incidentId":"INC-001","maxScore":80,"band":"HIGH",
                 "firstSeen":"2026-06-01T10:00:00Z","lastSeen":"2026-06-01T10:30:00Z",
                 "windowCount":3,"explanation":"brute force then port scan",
                 "users":["U001"],"sourceIps":["203.0.113.9"],"rules":["REPEATED_FAILED_LOGIN"]}
                """;
        mvc.perform(post("/api/incidents").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON).content(incident))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/incidents").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON).content(incident))
                .andExpect(status().isOk());

        mvc.perform(post("/api/alerts").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content(alert("ALERT-3", "INC-001")));

        mvc.perform(get("/api/incidents/INC-001").header("Authorization", "Bearer " + analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incident.users[0]").value("U001"))
                .andExpect(jsonPath("$.alerts[0].alertId").value("ALERT-3"));

        mvc.perform(get("/api/dashboard/summary").header("Authorization", "Bearer " + analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalIncidents").isNumber())
                .andExpect(jsonPath("$.alertsByBand.HIGH").isNumber())
                .andExpect(jsonPath("$.topIncidents").isArray());
    }

    @Test
    void unknownIncidentIsNotFound() throws Exception {
        String analyst = login("analyst", "analyst123");
        mvc.perform(get("/api/incidents/INC-999").header("Authorization", "Bearer " + analyst))
                .andExpect(status().isNotFound());
    }
}