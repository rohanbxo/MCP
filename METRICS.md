# ML model metrics

The DistilBERT injection classifier is trained offline (see
[`train/colab_train.ipynb`](train/colab_train.ipynb)). After a training run,
paste the held-out metrics and confusion matrix printed by `train/train.py` here
so the ML claim is backed by numbers, not just a hook.

> **Status:** _not yet trained_ — the firewall currently runs rules-only
> (`ml_available = false`). Fill this in after the first Colab run.

## Run details

| Field | Value |
|-------|-------|
| Base model | `distilbert-base-uncased` |
| Data | `deepset/prompt-injections` + `train/mcp_synthetic.jsonl` (204 rows) |
| Split | 80 / 20 stratified |
| Epochs | _e.g. 3_ |
| Date | _YYYY-MM-DD_ |

## Held-out results

| Metric | Value |
|--------|-------|
| Accuracy | _TBD_ |
| Precision | _TBD_ |
| Recall | _TBD_ |
| F1 | _TBD_ |

## Confusion matrix (rows = true, cols = pred) [benign, injection]

```
[[ _TBD_  _TBD_ ]
 [ _TBD_  _TBD_ ]]
```
