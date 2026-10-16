"""Fine-tunes microsoft/codebert-base into a binary secret/non-secret classifier
that powers the Layer 2 semantic engine (scanner/pattern_scanner.py findings get
re-checked here to cut false positives and catch context-obvious secrets Layer 1 misses).
"""

import json
import logging
from pathlib import Path
from typing import List, Tuple

import torch
import torch.nn as nn
from sklearn.metrics import f1_score, precision_score, recall_score
from torch.optim import AdamW
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModel, AutoTokenizer, PreTrainedTokenizerBase, get_linear_schedule_with_warmup

# Re-exported so existing `from ml.finetune import MAX_SEQ_LENGTH / split_context /
# build_input_text` callers are unaffected — the canonical definitions moved to
# ml/text_utils.py so ml/onnx_export.py can use them without importing this whole
# (torch+sklearn-heavy) module. See ml/text_utils.py's docstring for why.
from ml.text_utils import CONTEXT_WINDOW_LINES, MAX_SEQ_LENGTH, build_input_text, split_context

logger = logging.getLogger(__name__)

BASE_MODEL_NAME = "microsoft/codebert-base"
NUM_FROZEN_LAYERS = 6

DEFAULT_EPOCHS = 5
DEFAULT_BATCH_SIZE = 16
DEFAULT_LEARNING_RATE = 2e-5
WARMUP_RATIO = 0.1
EARLY_STOPPING_PATIENCE = 2

MODEL_SAVE_DIR = "ml/models/secret_classifier"


class SecretClassifier(nn.Module):
    """CodeBERT encoder (embeddings + first 6 layers frozen) + a small MLP head.

    Architecture: CodeBERT base -> Dropout(0.3) -> Linear(768, 256) -> ReLU
    -> Dropout(0.1) -> Linear(256, 2). The [CLS]-token hidden state is used
    as the pooled sequence representation fed into the head.
    """

    def __init__(self, base_model_name: str = BASE_MODEL_NAME) -> None:
        super().__init__()
        self.encoder = AutoModel.from_pretrained(base_model_name)
        self._freeze_first_n_layers(NUM_FROZEN_LAYERS)

        hidden_size = self.encoder.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Dropout(0.3),
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 2),
        )

    def _freeze_first_n_layers(self, n: int) -> None:
        """Freeze the embedding layer and the first n encoder layers to save memory/compute."""
        for param in self.encoder.embeddings.parameters():
            param.requires_grad = False
        for layer in self.encoder.encoder.layer[:n]:
            for param in layer.parameters():
                param.requires_grad = False

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        cls_hidden_state = outputs.last_hidden_state[:, 0, :]
        return self.classifier(cls_hidden_state)


class SecretDataset(Dataset):
    """Loads a JSONL file of {code_snippet, flagged_line, label, ...} samples."""

    def __init__(self, jsonl_path: str, tokenizer: PreTrainedTokenizerBase) -> None:
        with open(jsonl_path, encoding="utf-8") as f:
            self.samples = [json.loads(line) for line in f if line.strip()]
        self.tokenizer = tokenizer

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict:
        sample = self.samples[idx]
        text = build_input_text(self.tokenizer, sample["code_snippet"], sample["flagged_line"])
        encoding = self.tokenizer(
            text,
            truncation=True,
            max_length=MAX_SEQ_LENGTH,
            padding="max_length",
            add_special_tokens=False,  # already embedded manually in build_input_text
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label": torch.tensor(sample["label"], dtype=torch.long),
        }


def _class_weights(dataset: SecretDataset, device: torch.device) -> torch.Tensor:
    """Inverse-frequency class weights so CrossEntropyLoss doesn't favor the majority class."""
    labels = [s["label"] for s in dataset.samples]
    n = len(labels)
    n_pos = sum(labels)
    n_neg = n - n_pos
    weight_neg = n / (2 * n_neg) if n_neg else 1.0
    weight_pos = n / (2 * n_pos) if n_pos else 1.0
    return torch.tensor([weight_neg, weight_pos], dtype=torch.float, device=device)


@torch.no_grad()
def _evaluate(model: SecretClassifier, loader: DataLoader, device: torch.device) -> Tuple[float, float, float]:
    model.eval()
    all_preds: List[int] = []
    all_labels: List[int] = []
    for batch in loader:
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        logits = model(input_ids, attention_mask)
        preds = torch.argmax(logits, dim=1).cpu().tolist()
        all_preds.extend(preds)
        all_labels.extend(batch["label"].tolist())

    f1 = f1_score(all_labels, all_preds, zero_division=0)
    precision = precision_score(all_labels, all_preds, zero_division=0)
    recall = recall_score(all_labels, all_preds, zero_division=0)
    return f1, precision, recall


def _save_model(model: SecretClassifier, tokenizer: PreTrainedTokenizerBase, save_dir: str) -> None:
    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), save_path / "model.pt")
    tokenizer.save_pretrained(str(save_path))
    logger.info("Saved best model (by val F1) to %s", save_path)


def train(
    train_path: str = "data/train.jsonl",
    val_path: str = "data/val.jsonl",
    epochs: int = DEFAULT_EPOCHS,
    batch_size: int = DEFAULT_BATCH_SIZE,
    learning_rate: float = DEFAULT_LEARNING_RATE,
    save_dir: str = MODEL_SAVE_DIR,
) -> SecretClassifier:
    """Fine-tune SecretClassifier, printing per-epoch metrics and early-stopping on val F1."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cpu":
        logger.warning(
            "No GPU detected — training on CPU. This will be slow but will still complete."
        )

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)
    model = SecretClassifier().to(device)

    train_dataset = SecretDataset(train_path, tokenizer)
    val_dataset = SecretDataset(val_path, tokenizer)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)

    criterion = nn.CrossEntropyLoss(weight=_class_weights(train_dataset, device))
    trainable_params = [p for p in model.parameters() if p.requires_grad]
    optimizer = AdamW(trainable_params, lr=learning_rate)

    total_steps = len(train_loader) * epochs
    warmup_steps = int(total_steps * WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps
    )

    best_f1 = -1.0
    epochs_without_improvement = 0

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            scheduler.step()
            total_loss += loss.item()

        avg_loss = total_loss / max(1, len(train_loader))
        val_f1, val_precision, val_recall = _evaluate(model, val_loader, device)
        epoch_summary = (
            f"Epoch {epoch}/{epochs} | Loss: {avg_loss:.3f} | Val F1: {val_f1:.3f} "
            f"| Val Precision: {val_precision:.3f} | Val Recall: {val_recall:.3f}"
        )
        print(epoch_summary, flush=True)
        logger.info(epoch_summary)  # mirrored via logging so it survives even if stdout is lost

        if val_f1 > best_f1:
            best_f1 = val_f1
            epochs_without_improvement = 0
            _save_model(model, tokenizer, save_dir)
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= EARLY_STOPPING_PATIENCE:
                logger.info(
                    "Early stopping at epoch %d — val F1 hasn't improved for %d epochs",
                    epoch,
                    EARLY_STOPPING_PATIENCE,
                )
                break

    return model


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    train()
