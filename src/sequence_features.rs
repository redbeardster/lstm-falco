//! Агрегация временного окна шагов (каждый шаг — вектор одинаковой размерности)
//! в один вектор признаков для логистической «головы», как при офлайн-обучении в `train_lstm`.

pub fn sequence_to_features(sequence: &[Vec<f64>]) -> Vec<f64> {
    if sequence.is_empty() {
        return Vec::new();
    }

    let feature_dims = sequence[0].len();
    let mut features = Vec::new();

    for dim in 0..feature_dims {
        let values: Vec<f64> = sequence.iter().map(|step| step[dim]).collect();
        let n = values.len() as f64;
        let mean = values.iter().sum::<f64>() / n;
        let var: f64 = values.iter().map(|&v| (v - mean).powi(2)).sum::<f64>() / n;
        let std = var.sqrt();
        features.push(mean);
        features.push(std);
    }

    let window = 5usize;
    let denom = if sequence.len() > window {
        (sequence.len() - window) as f64
    } else {
        1.0
    };

    for dim in 0..feature_dims {
        let mut trend = 0.0;
        if sequence.len() > window {
            for i in window..sequence.len() {
                trend += sequence[i][dim] - sequence[i - window][dim];
            }
        }
        features.push(trend / denom);
    }

    features
}
