"""Load the saved model and its metadata, and score feature rows (Phase 7).

The service does NOT import the detection-engine code. Everything it needs
(the feature order, the version, the threshold) comes from the saved files.

Security note: the model is a pickled file (joblib). Load only model files you
created yourself, because loading a pickle can run code.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd

from .schemas import MODEL_FEATURE_FIELDS


class ModelNotFound(Exception):
    pass


class LoadedModel:
    def __init__(self, pipeline, meta: dict):
        self.pipeline = pipeline
        self.meta = meta
        self.version: str = meta["model_version"]
        self.algorithm: str = meta["algorithm"]
        self.features: list[str] = meta["features"]
        # LOF: decision = score_samples - offset_, and we report -score_samples.
        # So a window is flagged when its anomaly score is above -offset_.
        self.threshold = float(-pipeline.named_steps["lof"].offset_)

    def score(self, rows: list[dict]) -> tuple[list[float], list[bool]]:
        # DataFrame with column names, the same form the model was trained on.
        X = pd.DataFrame([{f: float(row[f]) for f in self.features} for row in rows],
                         columns=self.features)
        scores = (-self.pipeline.score_samples(X)).round(4).tolist()
        flags = (self.pipeline.predict(X) == -1).tolist()
        return scores, flags


def load_model(model_dir: Path, version: str) -> LoadedModel:
    model_path = model_dir / f"{version}.joblib"
    meta_path = model_dir / f"{version}.json"
    if not model_path.exists() or not meta_path.exists():
        raise ModelNotFound(f"model files not found in {model_dir} for version {version}")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta["features"] != MODEL_FEATURE_FIELDS:
        raise ValueError(
            "model features do not match the request schema: "
            f"model={meta['features']} schema={MODEL_FEATURE_FIELDS}"
        )
    return LoadedModel(joblib.load(model_path), meta)