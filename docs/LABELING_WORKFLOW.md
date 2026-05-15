# Labeling workflow — three approaches

## 1. Analyst labeling (primary, ground truth)

**Module:** `src/ml/labeling_queue.rs`

When the model flags an event as uncertain (active learning) or as a high-score anomaly (queue mode), it enters an in-memory **pending** queue. Analysts label via API; confirmed samples are appended to `data/labeled_anomalies.json` and fed into the training collector with source `analyst`.

### API

```bash
# Pending items for review
curl http://localhost:3000/api/ml/pending

# Label: true = real attack, false = false positive
curl -X POST http://localhost:3000/api/ml/label \
  -H 'Content-Type: application/json' \
  -d '{"id":"<uuid-from-pending>","is_real_attack":true}'

# All saved analyst labels
curl http://localhost:3000/api/ml/labeled

# Retrain LSTM on analyst-labeled file only
curl -X POST http://localhost:3000/api/ml/train_labeled
```

### Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `ML_LABELING_QUEUE` | `true` | Enqueue events for analyst review |
| `ML_LABELING_QUEUE_MAX` | `500` | Max pending items |
| `ML_LABELED_ANOMALIES_PATH` | `data/labeled_anomalies.json` | Persisted ground-truth samples |
| `ML_AUTO_RESPONSE_ON_ANOMALY` | `true` | Auto-trigger response when score > threshold **and** item was not queued |

If an event is queued for an analyst, automated response is **deferred** until you disable the queue or label it (configurable workflow for safe rollout).

---

## 2. Synthetic scenarios (CI / bootstrap)

**Example:** `cargo run --example training_scenarios`

Writes `data/training_data.json` (8-D timesteps). Use for:

- Initial bootstrap: `ML_BOOTSTRAP_TRAIN=true`
- API training: `POST /api/ml/train_real`
- CI regression: run scenarios + train + assert F1 does not drop

Deterministic labels; does not replace production traffic.

---

## 3. Active learning (minimize analyst effort)

**Enabled by default:** `ML_ACTIVE_LEARNING=true`

| LSTM score | Training label | Analyst queue |
|------------|----------------|---------------|
| ≥ `ML_AL_HIGH_CONFIDENCE` (0.9) | 1.0 (`active_learning`) | No |
| ≤ `ML_AL_LOW_CONFIDENCE` (0.3) | 0.0 (`active_learning`) | No |
| Between low and high | Proxy label skipped in collector | **Yes** (`uncertain_score`) |

Only **uncertain** events require human review; obvious normals and attacks auto-label for online training.

Manual rule overrides (`ML_LABELS_PATH`, `POST /api/ml/labels`) always take precedence.

---

## Recommended production loop

1. Run stack with `ML_ACTIVE_LEARNING=true` and `ML_LABELING_QUEUE=true`.
2. Analyst reviews `GET /api/ml/pending` daily.
3. `POST /api/ml/label` for each item.
4. Nightly cron: `curl -X POST http://localhost:3000/api/ml/train_labeled` (or merge labeled file into bootstrap dataset).
5. CI on every ML change: `training_scenarios` + `train_real` smoke test.

See [ML_ARCHITECTURE.md](./ML_ARCHITECTURE.md) for file formats and detection paths.
