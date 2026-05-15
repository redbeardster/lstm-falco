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
2. `ml::event_labeling::label_event` assigns a proxy label (**manual** → **rule heuristic** → **priority**). This replaces the old `if priority == "Critical" { 1.0 }` shortcut.
3. `DataCollector` stores events; every `ML_AUTO_TRAIN_SAMPLES` (default 500) triggers auto-train.
4. `RealtimeLSTM` scores each event; score above `ML_ANOMALY_THRESHOLD` triggers automated response.

## Data files

| File | Env var | Format |
|------|---------|--------|
| `data/lstm_model.json` | `ML_MODEL_PATH` | LSTM weights (`MODEL_VERSION` in `lstm_online.rs`) |
| `data/training_data.json` | `ML_TRAINING_DATA_PATH` | `[{ "timestep": [8 f64], "label": 0\|1, "source": "...", "rule": "..." }]` |
| `data/lstm_training.json` | `ML_COLLECTOR_PATH` | `[{ "event": FalcoEvent, "label": f64 }]` — runtime collector export |
| `data/labels.json` | `ML_LABELS_PATH` | `[{ "rule": "Rule Name", "label": 0.0\|1.0 }]` manual overrides |
| `data/training_metrics.json` | (fixed path in `main`) | Training run metrics + label source breakdown |
| `data/training_history.json` | (fixed path) | Training run history |

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

- `ML_BOOTSTRAP_TRAIN=true` — on startup, train from `training_data.json` if model missing or `ML_FORCE_RETRAIN=true`.
- `ML_FORCE_RETRAIN=true` — bootstrap overwrites existing `lstm_model.json`.
- See `src/ml/ml_config.rs` for window size, learning rate, thresholds, and paths.

## Module layout

All ML modules are under `src/ml/` (see `src/ml/mod.rs`). Integration with Falco/eBPF/API remains in `src/falco_integration.rs`, `src/ebpf_integration.rs`, and `src/main.rs`.

Status summary: [PROJECT_STATUS.md](./PROJECT_STATUS.md).

## Labeling note

Training labels use a **cascade** (see [LABELING_WORKFLOW.md](./LABELING_WORKFLOW.md)):

1. Analyst (`analyst`) — ground truth from `POST /api/ml/label`
2. Manual rules file (`manual`) — `ML_LABELS_PATH`
3. Active learning (`active_learning`) — auto 0/1 when score ≤0.3 or ≥0.9
4. Rule / priority heuristics — proxy only

Uncertain scores (0.3–0.9) skip auto-training until an analyst labels them.

## Examples

```bash
cargo run --example training_scenarios   # writes data/training_data.json (8-D)
cargo run --example train_simple_classifier  # offline demo only; NOT lstm_model.json
```

Production training: run the stack, collect events, or `POST /api/ml/train_real` after `training_scenarios`.
