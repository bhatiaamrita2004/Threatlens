"""ThreatLens ML service (Phase 7): serves the saved anomaly model over HTTP.

Endpoints:
- GET  /health   is the model loaded? (503 if not)
- POST /predict  score one or more user-windows; returns scores, flags and version

The service serves predictions. It does not replace the rules engine, and it
does not decide what is malicious. An anomaly score says "unusual", not "attack".

Run from the repo root:
    uvicorn app.main:app --app-dir ml-service --reload
Then open http://127.0.0.1:8000/docs for the interactive API page.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .model_store import load_model
from .schemas import HealthResponse, PredictRequest, PredictResponse, Prediction

logger = logging.getLogger("threatlens.ml")

DEFAULT_MODEL_DIR = Path(__file__).resolve().parents[1] / "models"   # ml-service/models
DEFAULT_VERSION = "lof-v2"


def create_app(model_dir: Path = DEFAULT_MODEL_DIR, version: str = DEFAULT_VERSION) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            app.state.model = load_model(model_dir, version)
            logger.info("loaded model %s", version)
        except Exception as exc:  # the service stays up; /health reports the problem
            app.state.model = None
            logger.error("model not loaded: %s", exc)
        yield

    app = FastAPI(title="ThreatLens ML service", version="0.7.0", lifespan=lifespan)
    app.state.model = None

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        details = []
        for err in exc.errors():
            parts = [str(p) for p in err["loc"] if p != "body"]
            details.append({"field": ".".join(parts) or "request", "message": err["msg"]})
        return JSONResponse(status_code=422, content={"error": "invalid_request", "details": details})

    @app.get("/health", response_model=HealthResponse, responses={503: {"model": HealthResponse}})
    def health(request: Request):
        model = request.app.state.model
        if model is None:
            body = HealthResponse(status="unavailable", model_loaded=False)
            return JSONResponse(status_code=503, content=body.model_dump())
        return HealthResponse(status="ok", model_loaded=True, model_version=model.version)

    @app.post("/predict", response_model=PredictResponse)
    def predict(req: PredictRequest, request: Request):
        model = request.app.state.model
        if model is None:
            raise HTTPException(status_code=503, detail="model not loaded; check /health")

        rows = [w.model_dump(exclude={"window_id"}) for w in req.windows]
        scores, flags = model.score(rows)
        predictions = [
            Prediction(window_id=w.window_id, anomaly_score=s, is_anomaly=f)
            for w, s, f in zip(req.windows, scores, flags)
        ]
        return PredictResponse(
            model_version=model.version,
            algorithm=model.algorithm,
            threshold=round(model.threshold, 4),
            count=len(predictions),
            predictions=predictions,
        )

    return app


app = create_app()