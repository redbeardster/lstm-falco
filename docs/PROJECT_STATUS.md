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

## Labeling and analyst queue

**Подробная документация:** [LABELING_WORKFLOW.md](./LABELING_WORKFLOW.md) (поток событий, таблицы по score, API, anti-patterns).

Кратко:

- В очередь `/api/ml/pending` попадают **только** uncertain: `ML_AL_LOW < score < ML_AL_HIGH` (default 0.3–0.9).
- Пока событие в очереди, **proxy-метка не пишется** в collector (`skip_collector`).
- `ML_ANOMALY_THRESHOLD` (0.7) управляет **автоответом**, не составом очереди.
- Ground truth: `POST /api/ml/label` → `data/labeled_anomalies.json`.

Training labels в collector (когда не ждём аналитика):

1. **Analyst** — после `POST /api/ml/label`
2. **Manual** — `ML_LABELS_PATH`
3. **Active learning** — score ≤ 0.3 или ≥ 0.9
4. **Rule / priority** — proxy only

## Module layout (reviewer note #4)

ML code lives under **`src/ml/`** with `src/ml/mod.rs`. Platform integration (`falco_integration`, `ebpf_integration`, API in `main.rs`) stays at `src/` root.

See also: [ML_ARCHITECTURE.md](./ML_ARCHITECTURE.md).
