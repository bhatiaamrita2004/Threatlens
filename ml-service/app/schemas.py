"""Request and response schemas for the ML service (Phase 7, Pydantic v2).

Every feature has a type and a range, so bad input is rejected with a 422 error
that names the field and says why. Unknown fields are rejected too, so a typo
in a feature name cannot silently become a missing value.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_COUNT = 1_000_000


class WindowFeatures(BaseModel):
    """One user-window, using the same columns the model was trained on (Phase 3)."""

    model_config = ConfigDict(extra="forbid")

    window_id: str | None = Field(default=None, max_length=100,
                                  description="Optional id, echoed back in the response")
    event_count: int = Field(ge=0, le=MAX_COUNT)
    failed_login_count: int = Field(ge=0, le=MAX_COUNT)
    login_success_count: int = Field(ge=0, le=MAX_COUNT)
    failure_ratio: float = Field(ge=0.0, le=1.0)
    offhours_login_count: int = Field(ge=0, le=MAX_COUNT)
    connection_count: int = Field(ge=0, le=MAX_COUNT)
    unique_ports: int = Field(ge=0, le=65_536)
    unique_source_ips: int = Field(ge=0, le=MAX_COUNT)
    unique_locations: int = Field(ge=0, le=1_000)
    request_count: int = Field(ge=0, le=MAX_COUNT)
    privilege_change_count: int = Field(ge=0, le=MAX_COUNT)

    @model_validator(mode="after")
    def logins_fit_inside_events(self) -> "WindowFeatures":
        if self.failed_login_count + self.login_success_count > self.event_count:
            raise ValueError("failed_login_count + login_success_count cannot exceed event_count")
        return self


# The feature names the model expects, in the order it was trained on.
MODEL_FEATURE_FIELDS = [name for name in WindowFeatures.model_fields if name != "window_id"]


class PredictRequest(BaseModel):
    windows: list[WindowFeatures] = Field(min_length=1, max_length=1000)


class Prediction(BaseModel):
    window_id: str | None
    anomaly_score: float = Field(description="Higher = more unusual. Compare with threshold.")
    is_anomaly: bool


class PredictResponse(BaseModel):
    model_version: str
    algorithm: str
    threshold: float = Field(description="Scores above this are flagged as anomalies.")
    count: int
    predictions: list[Prediction]


class HealthResponse(BaseModel):
    status: str                       # "ok" or "unavailable"
    model_loaded: bool
    model_version: str | None = None