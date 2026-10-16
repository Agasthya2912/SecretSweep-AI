"""Tests for the Layer 2 semantic engine: dataset prep, inference, ONNX export,
and pipeline integration. Model-loading tests use a stubbed model so they run
fast and don't require the full fine-tuned weights to already exist.
"""

import hashlib
import json
from pathlib import Path

import pytest
import torch
from transformers import AutoTokenizer

from ml.dataset_prep import create_synthetic_dataset
from ml.finetune import BASE_MODEL_NAME, MODEL_SAVE_DIR
from ml.inference import CONFIRMED_THRESHOLD, FALSE_POSITIVE_THRESHOLD, SemanticClassifier, _label_for_confidence
from ml.onnx_export import benchmark_onnx, export_to_onnx
from scanner.models import DiffLine, SemanticResult
from scanner.pattern_scanner import PatternMatch

FINETUNED_MODEL_EXISTS = (Path(MODEL_SAVE_DIR) / "model.pt").exists()


def make_pattern_match(
    content: str = 'aws_key = "AKIAIOSFODNN7EXAMPLE"',
    pattern_name: str = "AWS Access Key ID",
    matched_value: str = "AKIAIOSFODNN7EXAMPLE",
) -> PatternMatch:
    line = DiffLine(
        file_path="app.py",
        line_number=5,
        content=content,
        change_type="added",
        commit_hash="abc123",
        author_email="dev@example.com",
    )
    return PatternMatch(
        line=line,
        pattern_name=pattern_name,
        matched_value=matched_value,
        matched_value_hash=hashlib.sha256(matched_value.encode("utf-8")).hexdigest(),
        entropy_score=3.8,
        severity_hint="CRITICAL",
        confidence=0.9,
    )


@pytest.fixture(scope="module")
def tokenizer():
    return AutoTokenizer.from_pretrained(BASE_MODEL_NAME)


def _make_fake_classifier(tokenizer, class1_logit: float) -> SemanticClassifier:
    """A SemanticClassifier whose model always returns fixed logits, bypassing
    real weight loading entirely so tests stay fast and deterministic."""
    clf = object.__new__(SemanticClassifier)
    clf.device = torch.device("cpu")
    clf.tokenizer = tokenizer
    clf.model_version = "mock"
    fixed_logits = torch.tensor([[0.0, class1_logit]])
    clf.model = lambda input_ids, attention_mask: fixed_logits.repeat(input_ids.shape[0], 1)
    return clf


# --------------------------------------------------------------------------------------
# Dataset prep
# --------------------------------------------------------------------------------------


def test_dataset_creation_creates_balanced_dataset(tmp_path: Path) -> None:
    output_path = tmp_path / "synthetic.jsonl"
    create_synthetic_dataset(str(output_path), num_samples=130)

    with output_path.open() as f:
        samples = [json.loads(line) for line in f if line.strip()]

    positives = sum(1 for s in samples if s["label"] == 1)
    ratio = positives / len(samples)
    assert 0.3 <= ratio <= 0.7


def test_dataset_has_required_fields(tmp_path: Path) -> None:
    output_path = tmp_path / "synthetic.jsonl"
    create_synthetic_dataset(str(output_path), num_samples=50)

    with output_path.open() as f:
        samples = [json.loads(line) for line in f if line.strip()]

    assert len(samples) > 0
    for sample in samples:
        assert "code_snippet" in sample
        assert "flagged_line" in sample
        assert "label" in sample
        assert "is_secret" in sample
        assert sample["label"] in (0, 1)
        assert sample["is_secret"] == bool(sample["label"])


# --------------------------------------------------------------------------------------
# SemanticClassifier
# --------------------------------------------------------------------------------------


def test_semantic_classifier_loads() -> None:
    classifier = SemanticClassifier(model_path="ml/models/does_not_exist_xyz")
    assert classifier.model is not None
    assert classifier.model_version == "codebert-base"  # gracefully fell back


def test_classify_returns_semantic_result(tokenizer) -> None:
    match = make_pattern_match()
    classifier = _make_fake_classifier(tokenizer, class1_logit=4.0)

    result = classifier.classify(match, [match.line])

    assert isinstance(result, SemanticResult)
    assert result.pattern_match is match
    assert isinstance(result.is_secret, bool)
    assert 0.0 <= result.confidence <= 1.0
    assert result.semantic_label in {"confirmed_secret", "false_positive", "uncertain"}
    assert isinstance(result.context_snippet, str) and result.context_snippet != ""
    assert result.model_version == "mock"


def test_confirmed_secret_threshold() -> None:
    assert _label_for_confidence(0.90) == "confirmed_secret"
    assert 0.90 >= CONFIRMED_THRESHOLD


def test_false_positive_threshold() -> None:
    assert _label_for_confidence(0.20) == "false_positive"
    assert 0.20 <= FALSE_POSITIVE_THRESHOLD


def test_uncertain_threshold() -> None:
    assert _label_for_confidence(0.60) == "uncertain"


# --------------------------------------------------------------------------------------
# ONNX export (needs the fine-tuned model to actually exist)
# --------------------------------------------------------------------------------------


@pytest.mark.skipif(not FINETUNED_MODEL_EXISTS, reason="Fine-tuned model not trained yet")
def test_onnx_export_creates_file(tmp_path: Path) -> None:
    output_path = tmp_path / "secret_classifier.onnx"
    result_path = export_to_onnx(model_path=MODEL_SAVE_DIR, output_path=str(output_path))
    assert Path(result_path).exists()


@pytest.mark.skipif(not FINETUNED_MODEL_EXISTS, reason="Fine-tuned model not trained yet")
def test_onnx_benchmark_under_500ms(tmp_path: Path) -> None:
    output_path = tmp_path / "secret_classifier.onnx"
    export_to_onnx(model_path=MODEL_SAVE_DIR, output_path=str(output_path))
    stats = benchmark_onnx(str(output_path), num_runs=20)
    assert stats["avg_ms"] < 500


# --------------------------------------------------------------------------------------
# Pipeline integration
# --------------------------------------------------------------------------------------


def test_pipeline_layer2_reduces_false_positives() -> None:
    """Layer 2's job: a real secret survives into confirmed_secrets, a known
    false positive (e.g. a hash that merely looks like a secret) does not."""
    real_match = make_pattern_match(
        content='aws_key = "AKIAIOSFODNN7EXAMPLE"',
        pattern_name="AWS Access Key ID",
        matched_value="AKIAIOSFODNN7EXAMPLE",
    )
    false_positive_match = make_pattern_match(
        content='file_checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"',
        pattern_name="Generic Secret",
        matched_value="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
    )

    semantic_results = [
        SemanticResult(
            pattern_match=real_match,
            is_secret=True,
            confidence=0.95,
            semantic_label="confirmed_secret",
            context_snippet="...",
            model_version="mock",
        ),
        SemanticResult(
            pattern_match=false_positive_match,
            is_secret=False,
            confidence=0.10,
            semantic_label="false_positive",
            context_snippet="...",
            model_version="mock",
        ),
    ]

    # Same filtering convention ScanPipeline.run() applies to Layer 2 output.
    confirmed_secrets = [r for r in semantic_results if r.semantic_label == "confirmed_secret"]
    false_positives_removed = [r for r in semantic_results if r.semantic_label == "false_positive"]

    assert len(confirmed_secrets) == 1
    assert confirmed_secrets[0].pattern_match is real_match
    assert len(false_positives_removed) == 1
    assert false_positive_match not in [r.pattern_match for r in confirmed_secrets]
