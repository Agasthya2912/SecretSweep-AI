"""Pure-Python text/context helpers shared by the training, inference, and
ONNX-export paths — deliberately free of torch/sklearn imports.

ml/finetune.py and ml/inference.py re-export these names for backward
compatibility (existing `from ml.finetune import build_input_text` etc.
callers are unaffected). ml/onnx_export.py imports directly from here
instead, so loading ONNXClassifier for the pre-commit hook doesn't drag in
ml/finetune.py's training-only dependencies (sklearn, torch.optim,
torch.utils.data) it never uses. Note this does NOT avoid importing torch
itself — `transformers.AutoTokenizer` (needed either way, for the CLS/SEP
tokens and tokenization) transitively imports torch regardless; see
hooks/hook.py's fast_mode for the pattern-only path that avoids this.
"""

from typing import Tuple

MAX_SEQ_LENGTH = 512
CONTEXT_WINDOW_LINES = 10

CONFIRMED_THRESHOLD = 0.85
FALSE_POSITIVE_THRESHOLD = 0.30


def split_context(code_snippet: str, flagged_line: str) -> Tuple[str, str]:
    """Split code_snippet into up to 10 lines of context before/after flagged_line."""
    lines = code_snippet.split("\n")
    try:
        idx = lines.index(flagged_line)
    except ValueError:
        idx = len(lines) // 2  # flagged_line not found verbatim — fall back to the midpoint

    before = lines[max(0, idx - CONTEXT_WINDOW_LINES) : idx]
    after = lines[idx + 1 : idx + 1 + CONTEXT_WINDOW_LINES]
    return "\n".join(before), "\n".join(after)


def build_input_text(tokenizer, code_snippet: str, flagged_line: str) -> str:
    """Build the "[CLS] context_before [SEP] flagged_line [SEP] context_after" input string.

    CodeBERT is RoBERTa-based, so its real special tokens are <s>/</s> rather than the
    literal strings "[CLS]"/"[SEP]" — tokenizer.cls_token/sep_token are used here so the
    boundary markers are tokens the model actually recognizes, while preserving the
    3-part [CLS]-before-[SEP]-flagged-[SEP]-after structure.
    """
    context_before, context_after = split_context(code_snippet, flagged_line)
    return (
        f"{tokenizer.cls_token} {context_before} {tokenizer.sep_token} "
        f"{flagged_line} {tokenizer.sep_token} {context_after}"
    )


def label_for_confidence(confidence: float) -> str:
    """confidence >= 0.85 -> confirmed_secret; <= 0.30 -> false_positive; else uncertain."""
    if confidence >= CONFIRMED_THRESHOLD:
        return "confirmed_secret"
    if confidence <= FALSE_POSITIVE_THRESHOLD:
        return "false_positive"
    return "uncertain"


def build_context_snippet(pattern_match, context_lines) -> Tuple[str, str]:
    """Build the ~20-line window: 10 lines before + the flagged line + 10 lines after.

    context_lines is restricted to the flagged line's own file and ordered by
    line number so the window reads as real surrounding source, not diff noise
    from unrelated files in the same commit.
    """
    flagged = pattern_match.line
    same_file_lines = sorted(
        (line for line in context_lines if line.file_path == flagged.file_path),
        key=lambda line: line.line_number,
    )

    idx = next(
        (
            i
            for i, line in enumerate(same_file_lines)
            if line.line_number == flagged.line_number and line.content == flagged.content
        ),
        None,
    )
    if idx is None:
        same_file_lines = [flagged]
        idx = 0

    before = same_file_lines[max(0, idx - CONTEXT_WINDOW_LINES) : idx]
    after = same_file_lines[idx + 1 : idx + 1 + CONTEXT_WINDOW_LINES]

    snippet = "\n".join([line.content for line in before] + [flagged.content] + [line.content for line in after])
    return snippet, flagged.content
