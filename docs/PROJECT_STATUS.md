# Project status — ML / detection

Last updated to match the current codebase (not legacy `lstm_detector` / hybrid Falco scoring).

## Falco path: LSTM is integrated

| Component | Module | Status |
|-----------|--------|--------|
| Online inference + BPTT training | `src/ml/lstm_online.rs`, `lstm_cell`, `lstm_bptt` | **Production** |
| Webhook orchestration | `src/ml/realtime_lstm.rs` (`RealtimeLSTM`) | **Production** |
| Falco handler | `src/falco_integration.rs` | **Production** |

**There is no hybrid z-score + LSTM score in `falco_integration.rs`.** Falco anomalies use a single LSTM score from `RealtimeLSTM::process_event`. Z-score runs only on the **eBPF syscall duration** path (`src/ebpf_zscore_detector.rs`).

### Naming history (reviewer note #1)

| Old name | Current name |
|----------|----------------|
| `time_window_detector.rs` / `lstm_detector.rs` | `src/ml/realtime_lstm.rs` |
| Field `self.lstm_detector` | `self.detector: Arc<LSTMOnlineDetector>` inside `RealtimeLSTM` |
| `LSTMDetector` | `RealtimeLSTM` + `LSTMOnlineDetector` |

If you still see `self.lstm_detector` or `time_window_detector.rs`, you are on an outdated branch.

## Other detection paths

| Path | Module | Algorithm |
|------|--------|-----------|
| eBPF | `ebpf_zscore_detector` | Syscall duration z-score |
| Composite API | `heuristic_threat_detector` | Weighted severity heuristic (not neural net) |

## Real-time labeling (reviewer note #3)

Training labels in the live collector are **not** `Critical → 1.0` only.

Priority in `falco_integration.rs` is assigned via `ml::event_labeling::label_event`:

1. **Manual** — `data/labels.json` (`ML_LABELS_PATH`), updatable via `POST /api/ml/labels`
2. **Rule heuristics** — attack/noise rule name patterns and tags
3. **Priority fallback** — `Critical` / `Alert` / `Emergency` / `Error` → 1.0

Priority labels remain **proxies**, not confirmed incidents. For field-quality training, maintain manual rule labels and/or bootstrap from curated `training_data.json`.

## Module layout (reviewer note #4)

ML code lives under **`src/ml/`** with `src/ml/mod.rs`. Platform integration (`falco_integration`, `ebpf_integration`, API in `main.rs`) stays at `src/` root.

See also: [ML_ARCHITECTURE.md](./ML_ARCHITECTURE.md).
