"""Shared PyTorch inference wrapper for the Layer 2 semantic engine.

Loads the fine-tuned SecretClassifier (falling back to un-fine-tuned base
CodeBERT if no trained weights exist yet) and turns Layer 1 PatternMatch
findings into SemanticResult verdicts.
"""

import logging
from pathlib import Path
from typing import List, Tuple

import torch
from transformers import AutoTokenizer

from ml.finetune import BASE_MODEL_NAME, MODEL_SAVE_DIR, SecretClassifier
# Re-exported under their old private names so existing callers (ml/onnx_export.py,
# tests) importing `_label_for_confidence` / `_build_context_snippet` from here are
# unaffected — canonical definitions now live in ml/text_utils.py.
from ml.text_utils import CONFIRMED_THRESHOLD, FALSE_POSITIVE_THRESHOLD, MAX_SEQ_LENGTH
from ml.text_utils import build_context_snippet as _build_context_snippet
from ml.text_utils import build_input_text, label_for_confidence as _label_for_confidence
from scanner.models import DiffLine, SemanticResult
from scanner.pattern_scanner import PatternMatch

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 8

# Keyed by model_path: (tokenizer, model, model_version, device). Loading CodeBERT off
# disk (AutoTokenizer.from_pretrained + load_state_dict) measured at 6-31s depending on
# OS page-cache warmth — real cost, not startup noise. ScanPipeline() is constructed
# fresh per Celery task (api/tasks/scan_task.py), but a worker process handles many
# tasks over its life, so without this cache every single scan paid that cost again,
# even back-to-back scans of the same repo seconds apart. Process-global by design: each
# Celery prefork child gets its own module state, so this caches per worker process,
# not across processes — exactly matching "load once per long-lived process."
_MODEL_CACHE: dict = {}


class SemanticClassifier:
    """Layer 2: CodeBERT-based semantic secret/non-secret classifier."""

    def __init__(self, model_path: str = MODEL_SAVE_DIR) -> None:
        """Load the fine-tuned model from model_path, or fall back to base CodeBERT.

        Reuses a previously loaded model for the same model_path within this process
        (see _MODEL_CACHE) instead of hitting disk again.
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        if self.device.type == "cpu":
            logger.warning("No GPU detected — running Layer 2 inference on CPU.")

        cached = _MODEL_CACHE.get(model_path)
        if cached is not None:
            self.tokenizer, self.model, self.model_version = cached
            logger.info("Reusing cached SecretClassifier for %s (skipped disk load)", model_path)
        else:
            weights_path = Path(model_path) / "model.pt"
            if weights_path.exists():
                self.tokenizer = AutoTokenizer.from_pretrained(model_path)
                self.model = SecretClassifier(BASE_MODEL_NAME)
                self.model.load_state_dict(torch.load(weights_path, map_location=self.device))
                self.model_version = "codebert-finetuned"
                logger.info("Loaded fine-tuned SecretClassifier from %s", model_path)
            else:
                logger.warning(
                    "No fine-tuned model found at %s — falling back to base CodeBERT. "
                    "Its classification head is untrained, so confidence scores won't be "
                    "meaningful until ml/finetune.py has been run.",
                    model_path,
                )
                self.tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)
                self.model = SecretClassifier(BASE_MODEL_NAME)
                self.model_version = "codebert-base"
            self.model.to(self.device)
            self.model.eval()
            _MODEL_CACHE[model_path] = (self.tokenizer, self.model, self.model_version)

    def _encode(self, texts: List[str]) -> dict:
        # padding=True pads only to the longest sequence in *this* call, not always to
        # MAX_SEQ_LENGTH. Attention masking makes the two mathematically equivalent for
        # every real token — padding amount never changes a model's output — so this is
        # a pure speedup, not a behavior change. ml/onnx_export.py's ONNXClassifier
        # already made this exact switch (see its _run()'s comment: fixed 512-token
        # padding was measured at ~880ms per call vs. a fraction of that for realistic
        # ~20-line snippets); this path serves every scan the Celery worker runs and was
        # missed when that fix landed.
        encoding = self.tokenizer(
            texts,
            truncation=True,
            max_length=MAX_SEQ_LENGTH,
            padding=True,
            add_special_tokens=False,
            return_tensors="pt",
        )
        return {k: v.to(self.device) for k, v in encoding.items()}

    def classify(self, pattern_match: PatternMatch, context_lines: List[DiffLine]) -> SemanticResult:
        """Classify a single PatternMatch using its surrounding diff context."""
        snippet, flagged_content = _build_context_snippet(pattern_match, context_lines)
        text = build_input_text(self.tokenizer, snippet, flagged_content)
        encoding = self._encode([text])

        with torch.no_grad():
            logits = self.model(encoding["input_ids"], encoding["attention_mask"])
            confidence = torch.softmax(logits, dim=1)[0, 1].item()

        label = _label_for_confidence(confidence)
        return SemanticResult(
            pattern_match=pattern_match,
            is_secret=confidence >= 0.5,
            confidence=round(confidence, 4),
            semantic_label=label,
            context_snippet=snippet,
            model_version=self.model_version,
        )

    def classify_batch(
        self, items: List[Tuple[PatternMatch, List[DiffLine]]]
    ) -> List[SemanticResult]:
        """Classify many (PatternMatch, context_lines) pairs in batches of 8 for efficiency."""
        results: List[SemanticResult] = []

        for start in range(0, len(items), DEFAULT_BATCH_SIZE):
            chunk = items[start : start + DEFAULT_BATCH_SIZE]
            snippets: List[str] = []
            texts: List[str] = []
            for pattern_match, context_lines in chunk:
                snippet, flagged_content = _build_context_snippet(pattern_match, context_lines)
                snippets.append(snippet)
                texts.append(build_input_text(self.tokenizer, snippet, flagged_content))

            encoding = self._encode(texts)
            with torch.no_grad():
                logits = self.model(encoding["input_ids"], encoding["attention_mask"])
                confidences = torch.softmax(logits, dim=1)[:, 1].tolist()

            for (pattern_match, _), snippet, confidence in zip(chunk, snippets, confidences):
                label = _label_for_confidence(confidence)
                results.append(
                    SemanticResult(
                        pattern_match=pattern_match,
                        is_secret=confidence >= 0.5,
                        confidence=round(confidence, 4),
                        semantic_label=label,
                        context_snippet=snippet,
                        model_version=self.model_version,
                    )
                )

        return results
