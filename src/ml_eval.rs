//! Метрики бинарной классификации для обучения/валидации LSTM.

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ClassificationMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub loss: f64,
    pub samples: usize,
}

pub fn binary_metrics(
    predictions: &[f64],
    labels: &[f64],
    threshold: f64,
) -> ClassificationMetrics {
    if predictions.is_empty() || predictions.len() != labels.len() {
        return ClassificationMetrics::default();
    }

    let mut correct = 0;
    let mut tp = 0;
    let mut fp = 0;
    let mut fn_count = 0;
    let mut loss = 0.0;

    for (&pred, &label) in predictions.iter().zip(labels.iter()) {
        let err = pred - label;
        loss += err * err;
        let predicted = pred > threshold;
        let actual = label > 0.5;
        if predicted == actual {
            correct += 1;
        }
        match (predicted, actual) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, true) => fn_count += 1,
            _ => {}
        }
    }

    let n = predictions.len() as f64;
    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + fn_count > 0 {
        tp as f64 / (tp + fn_count) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    ClassificationMetrics {
        accuracy: correct as f64 / n,
        precision,
        recall,
        f1_score: f1,
        loss: loss / n,
        samples: predictions.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_predictions() {
        let preds = vec![0.9, 0.1, 0.8, 0.2];
        let labels = vec![1.0, 0.0, 1.0, 0.0];
        let m = binary_metrics(&preds, &labels, 0.5);
        assert!((m.accuracy - 1.0).abs() < 1e-9);
        assert!((m.f1_score - 1.0).abs() < 1e-9);
    }
}
