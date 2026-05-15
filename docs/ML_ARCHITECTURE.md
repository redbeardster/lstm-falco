# ML Architecture

This stack uses **three independent detection paths**. Only the Falco webhook path runs the online LSTM.

## Detection paths

| Path | Module | Algorithm | Trigger |
|------|--------|-----------|---------|
| Falco webhook | `ml/realtime_lstm`, `ml/lstm_online`, `ml/lstm_cell`, `ml/lstm_bptt` | Online LSTM + sigmoid head (single score; **no** z-score blend) | `POST /falco-events` |
| eBPF syscalls | `ebpf_zscore_detector` | Per-syscall duration z-score (separate path) | eBPF event stream |
| Composite API | `heuristic_threat_detector` | Weighted severity heuristic | `CompositeDetector` on `SecurityEvent` |

## Falco LSTM pipeline

1. Webhook receives `FalcoEvent`.
2. `RealtimeLSTM::process_event` returns LSTM `score` (single head, no z-score blend on this path).
3. `ml::labeling_queue::resolve_training_label` decides collector vs analyst queue (see [LABELING_WORKFLOW.md](./LABELING_WORKFLOW.md)):
   - **Uncertain band** (`ML_AL_LOW` < score < `ML_AL_HIGH`): pending queue only, **no** proxy label in collector.
   - **High confidence** (active learning): auto `1.0` / `0.0` in collector.
   - **Otherwise**: proxy cascade in `event_labeling` (manual → rule → priority).
4. `DataCollector` accumulates labeled steps; every `ML_AUTO_TRAIN_SAMPLES` (default 500) triggers auto-train.
5. If `score > ML_ANOMALY_THRESHOLD` and the event was **not** queued for analyst → `AutomatedResponseEngine`.

**Not used anymore:** `if priority == "Critical" { 1.0 }` as the only label; queueing all alerts with `score > 0.7`; hybrid `combined_score`.

## Data files

| File | Env var | Format |
|------|---------|--------|
| `data/lstm_model.json` | `ML_MODEL_PATH` | LSTM weights (`MODEL_VERSION` in `lstm_online.rs`) |
| `data/training_data.json` | `ML_TRAINING_DATA_PATH` | `[{ "timestep": [8 f64], "label": 0\|1, "source": "...", "rule": "..." }]` |
| `data/lstm_training.json` | `ML_COLLECTOR_PATH` | `[{ "event": FalcoEvent, "label": f64 }]` — runtime collector export |
| `data/labels.json` | `ML_LABELS_PATH` | `[{ "rule": "Rule Name", "label": 0.0\|1.0 }]` manual overrides |
| `data/training_metrics.json` | (fixed path in `main`) | Training run metrics + label source breakdown |
| `data/training_history.json` | (fixed path) | Training run history |
| `data/labeled_anomalies.json` | `ML_LABELED_ANOMALIES_PATH` | Analyst-confirmed samples (`POST /api/ml/label`) |

Legacy `"features"` key in `training_data.json` is accepted if the vector length is 8.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/falco-events` | Ingest Falco event (webhook) |
| GET | `/ml/status` | ML buffer + LSTM stats (on webhook port) |
| POST | `/api/ml/train` | Train from in-memory collector |
| POST | `/api/ml/train_real` | Train from `training_data.json` |
| GET | `/api/ml/stats` | Collector + LSTM summary |
| GET | `/api/ml/lstm` | LSTM detector stats |
| GET | `/api/ml/metrics` | Training metrics history |
| POST | `/api/ml/save` | Flush collector to `ML_COLLECTOR_PATH` |
| GET | `/api/ml/labels` | List manual rule labels + collector label-source stats |
| POST | `/api/ml/labels` | Upsert `{ "rule", "label" }` into `ML_LABELS_PATH` |
| POST | `/api/ml/labels/reload` | Reload `ML_LABELS_PATH` from disk |
| GET | `/api/ml/pending` | Analyst queue: uncertain / flagged events |
| POST | `/api/ml/label` | Analyst confirms `{ "id", "is_real_attack" }` |
| GET | `/api/ml/labeled` | List persisted analyst labels |
| POST | `/api/ml/train_labeled` | Train from `ML_LABELED_ANOMALIES_PATH` |

## Environment variables

| Variable | Default | Role |
|----------|---------|------|
| `ML_ANOMALY_THRESHOLD` | `0.7` | Automated **response** threshold (not the analyst queue) |
| `ML_AL_LOW_CONFIDENCE` | `0.3` | Lower bound of uncertain band (exclusive) |
| `ML_AL_HIGH_CONFIDENCE` | `0.9` | Upper bound of uncertain band (exclusive) |
| `ML_ACTIVE_LEARNING` | `true` | Auto-label confident scores in collector |
| `ML_LABELING_QUEUE` | `true` | Enable analyst queue for uncertain scores only |
| `ML_AUTO_RESPONSE_ON_ANOMALY` | `true` | Skip response while event is in pending queue |
| `ML_BOOTSTRAP_TRAIN` | `false` | Train from `training_data.json` on startup if no model |
| `ML_FORCE_RETRAIN` | `false` | Bootstrap overwrites existing model |

Full labeling semantics: [LABELING_WORKFLOW.md](./LABELING_WORKFLOW.md). All keys: `src/ml/ml_config.rs`.

## Module layout

All ML modules are under `src/ml/` (see `src/ml/mod.rs`). Integration with Falco/eBPF/API remains in `src/falco_integration.rs`, `src/ebpf_integration.rs`, and `src/main.rs`.

Status summary: [PROJECT_STATUS.md](./PROJECT_STATUS.md).

## Labeling (summary)

Detailed flow, anti-patterns, and score tables: **[LABELING_WORKFLOW.md](./LABELING_WORKFLOW.md)**.

Short version: only `ML_AL_LOW < score < ML_AL_HIGH` goes to `/api/ml/pending` without a proxy label in the training buffer. Analyst labels become ground truth in `labeled_anomalies.json`.

## Examples

```bash
cargo run --example training_scenarios   # writes data/training_data.json (8-D)
cargo run --example train_simple_classifier  # offline demo only; NOT lstm_model.json
```

Production training: run the stack, collect events, or `POST /api/ml/train_real` after `training_scenarios`.
