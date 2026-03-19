"""
Isolation Forest-based anomaly detector.
Trains on clean baseline feature vectors; scores new traffic.
Model is persisted to disk and reloaded across restarts.
"""
from __future__ import annotations

import asyncio
import os
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest  # type: ignore
import joblib  # type: ignore

from app.core.logger import get_logger

log = get_logger("anomaly_model")

_MODEL_PATH = "./models/isolation_forest.joblib"
_model: Optional[IsolationForest] = None
_buffer: list[list[float]] = []  # Feature vectors accumulated before training
_TRAIN_THRESHOLD = 500           # Min samples before first training


def _features_to_vector(features: dict) -> list[float]:
    """Convert raw feature dict to numeric vector for ML."""
    protocol_map = {"tcp": 1.0, "udp": 2.0, "icmp": 3.0, "other": 0.0}
    return [
        float(features.get("pkt_len", 0)),
        float(features.get("dst_port", 0) or 0),
        float(features.get("is_syn", False)),
        float(features.get("is_ack", False)),
        float(features.get("is_rst", False)),
        protocol_map.get(features.get("protocol", "other"), 0.0),
    ]


def _load_model() -> None:
    global _model
    if os.path.exists(_MODEL_PATH):
        _model = joblib.load(_MODEL_PATH)
        log.info("anomaly_model.loaded", path=_MODEL_PATH)


def _save_model() -> None:
    os.makedirs(os.path.dirname(_MODEL_PATH), exist_ok=True)
    joblib.dump(_model, _MODEL_PATH)
    log.info("anomaly_model.saved", path=_MODEL_PATH)


def _train() -> None:
    global _model, _buffer
    if len(_buffer) < _TRAIN_THRESHOLD:
        return
    X = np.array(_buffer)
    _model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    _model.fit(X)
    _save_model()
    log.info("anomaly_model.trained", samples=len(_buffer))
    _buffer = []  # reset buffer after training


def score(features: dict) -> float:
    """
    Return anomaly score in [0.0, 1.0].
    0.0 = normal, 1.0 = highly anomalous.
    Returns 0.0 if model not yet trained.
    """
    if _model is None:
        # Accumulate training data
        _buffer.append(_features_to_vector(features))
        if len(_buffer) >= _TRAIN_THRESHOLD:
            _train()
        return 0.0

    vec = np.array([_features_to_vector(features)])
    # decision_function: more negative = more anomalous
    raw = _model.decision_function(vec)[0]
    # Normalize: map [-0.5, 0.5] → [1.0, 0.0]
    normalized = float(max(0.0, min(1.0, 0.5 - raw)))
    return round(normalized, 4)


async def retrain_model_if_needed() -> None:
    """Scheduler job — re-train if we have enough new samples."""
    if len(_buffer) >= _TRAIN_THRESHOLD:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _train)


# Load model at import time
_load_model()
