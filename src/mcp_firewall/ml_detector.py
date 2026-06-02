"""Pluggable DistilBERT detector with a graceful fallback (build spec Section 8).

The ML model is *optional*. If `transformers`/`torch` are missing, or no model
is present in ``model_dir``, the detector reports ``available == False`` and the
firewall proceeds with rules only. Loading never raises.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("mcp_firewall.ml")

DEFAULT_MODEL_DIR = "./model"

# Label index -> class name. A model fine-tuned by train/train.py uses
# 0 = benign, 1 = injection. This is overridden by the model's id2label if set.
_DEFAULT_ID2LABEL = {0: "benign", 1: "injection"}


class MLDetector:
    """Wraps a DistilBERT sequence classifier; degrades to a no-op if absent."""

    def __init__(self, model_dir: str | None = None) -> None:
        self._model_dir = model_dir or DEFAULT_MODEL_DIR
        self._available = False
        self._tokenizer = None
        self._model = None
        self._torch = None
        self._id2label = dict(_DEFAULT_ID2LABEL)
        self._try_load()

    # ------------------------------------------------------------------ #
    def _try_load(self) -> None:
        """Best-effort load. Any failure -> available=False, warn, no raise."""
        if not os.path.isdir(self._model_dir):
            logger.warning(
                "ML model dir %r not found; ML detector disabled (rules only).",
                self._model_dir,
            )
            return
        try:
            import torch  # noqa: F401
            from transformers import (  # type: ignore
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            self._torch = torch
            self._tokenizer = AutoTokenizer.from_pretrained(self._model_dir)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self._model_dir
            )
            self._model.eval()

            cfg_labels = getattr(self._model.config, "id2label", None)
            if cfg_labels:
                # transformers stores keys as ints already, but normalize.
                self._id2label = {
                    int(k): str(v).lower() for k, v in cfg_labels.items()
                }
            self._available = True
            logger.info("ML detector loaded from %r.", self._model_dir)
        except Exception as exc:  # pragma: no cover - exercised only with deps
            self._available = False
            self._model = None
            self._tokenizer = None
            logger.warning(
                "Failed to load ML model from %r (%s); ML detector disabled "
                "(rules only).",
                self._model_dir,
                exc,
            )

    # ------------------------------------------------------------------ #
    @property
    def available(self) -> bool:
        """True only if a model loaded successfully."""
        return self._available

    def score(self, text: str) -> tuple[str, float]:
        """Return (label, confidence).

        label is "injection" or "benign". When unavailable, returns
        ("benign", 0.0) so callers can treat it uniformly.
        """
        if not self._available or not text:
            return ("benign", 0.0)
        try:  # pragma: no cover - exercised only with deps
            torch = self._torch
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            )
            with torch.no_grad():
                logits = self._model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0]
            idx = int(torch.argmax(probs).item())
            label = self._id2label.get(idx, "benign")
            confidence = float(probs[idx].item())
            return (label, confidence)
        except Exception as exc:  # pragma: no cover
            logger.warning("ML scoring failed (%s); returning benign.", exc)
            return ("benign", 0.0)
