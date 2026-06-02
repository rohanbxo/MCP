"""Fine-tune DistilBERT for MCP prompt-injection detection.

Run on Google Colab/Kaggle (free GPU). Do not run in the build sandbox.

This script (build spec Section 14):
  * loads the `deepset/prompt-injections` dataset (via `datasets`) and the local
    `train/mcp_synthetic.jsonl` of MCP-specific poisoned descriptions/responses,
  * fine-tunes `distilbert-base-uncased` for binary classification
    (0 = benign, 1 = injection) with `transformers.Trainer`,
  * saves the model + tokenizer to `./model`,
  * prints accuracy / precision / recall / F1 and a confusion matrix on a
    held-out split.

Install (Colab):
    pip install "transformers>=4.38" "torch>=2.2" "datasets>=2.18" "scikit-learn>=1.4"

Usage:
    python train/train.py --out ./model --epochs 3
"""

from __future__ import annotations

import argparse
import json
import os

LABELS = {0: "benign", 1: "injection"}


def load_synthetic(path: str) -> list[dict]:
    rows: list[dict] = []
    if not os.path.exists(path):
        print(f"[warn] synthetic file {path!r} not found; skipping.")
        return rows
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                obj = json.loads(line)
                rows.append({"text": obj["text"], "label": int(obj["label"])})
    print(f"[data] loaded {len(rows)} synthetic MCP rows from {path}")
    return rows


def load_public() -> list[dict]:
    """Load deepset/prompt-injections; maps its labels to 0/1.

    The dataset uses label 1 = injection, 0 = legitimate, matching ours.
    """
    from datasets import load_dataset  # local import: only needed for training

    rows: list[dict] = []
    try:
        ds = load_dataset("deepset/prompt-injections")
        for split in ds:
            for ex in ds[split]:
                text = ex.get("text") or ex.get("prompt") or ""
                label = int(ex.get("label", 0))
                if text:
                    rows.append({"text": text, "label": label})
        print(f"[data] loaded {len(rows)} rows from deepset/prompt-injections")
    except Exception as exc:  # network / dataset issues shouldn't be fatal
        print(f"[warn] could not load public dataset ({exc}); using synthetic only.")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune DistilBERT for MCP injection detection.")
    parser.add_argument("--out", default="./model", help="Output dir for model + tokenizer.")
    parser.add_argument("--synthetic", default="train/mcp_synthetic.jsonl")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--base-model", default="distilbert-base-uncased")
    args = parser.parse_args()

    # Heavy imports are intentionally local so this file imports cleanly without
    # torch/transformers/datasets installed (the build sandbox never trains).
    import numpy as np
    from datasets import Dataset
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    )
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
        set_seed,
    )

    set_seed(args.seed)

    rows = load_public() + load_synthetic(args.synthetic)
    if not rows:
        raise SystemExit("No training data available.")

    from datasets import ClassLabel
    ds = Dataset.from_list(rows).shuffle(seed=args.seed)
    # Cast label to ClassLabel so stratified split works regardless of whether
    # the source dataset stored labels as plain ints (Value) or ClassLabel.
    ds = ds.cast_column("label", ClassLabel(names=["benign", "injection"]))
    split = ds.train_test_split(test_size=0.2, seed=args.seed, stratify_by_column="label")
    train_ds, eval_ds = split["train"], split["test"]

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)

    def tokenize(batch):
        return tokenizer(
            batch["text"], truncation=True, max_length=args.max_length
        )

    train_ds = train_ds.map(tokenize, batched=True)
    eval_ds = eval_ds.map(tokenize, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=2,
        id2label=LABELS,
        label2id={v: k for k, v in LABELS.items()},
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, preds, average="binary", zero_division=0
        )
        return {
            "accuracy": accuracy_score(labels, preds),
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    training_args = TrainingArguments(
        output_dir=os.path.join(args.out, "_checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=20,
        seed=args.seed,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
    )

    trainer.train()
    metrics = trainer.evaluate()
    print("\n=== Held-out metrics ===")
    for k, v in metrics.items():
        if isinstance(v, float):
            print(f"{k}: {v:.4f}")

    preds = np.argmax(trainer.predict(eval_ds).predictions, axis=-1)
    labels = np.array(eval_ds["label"])
    print("\nConfusion matrix (rows=true, cols=pred) [benign, injection]:")
    print(confusion_matrix(labels, preds))

    os.makedirs(args.out, exist_ok=True)
    trainer.save_model(args.out)
    tokenizer.save_pretrained(args.out)
    print(f"\nSaved model + tokenizer to {args.out!r}.")


if __name__ == "__main__":
    main()
