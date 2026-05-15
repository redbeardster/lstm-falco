// examples/train_lstm.rs

#[path = "../src/sequence_features.rs"]
mod sequence_features;

use nalgebra as na;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::Deserialize;
use sequence_features::sequence_to_features;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct TrainingSample {
    sequence: Vec<Vec<f64>>,
    label: f64,
    #[allow(dead_code)]
    attack_type: Option<String>,
}

// Простая нейронная сеть для детекции аномалий
struct SimpleClassifier {
    weights: na::DVector<f64>,
    bias: f64,
}

impl SimpleClassifier {
    fn new(input_size: usize) -> Self {
        let mut rng = rand::thread_rng();
        let weights = na::DVector::from_fn(input_size, |_, _| rng.gen_range(-0.1..0.1));
        Self {
            weights,
            bias: 0.0,
        }
    }

    // Сигмоид
    fn sigmoid(x: f64) -> f64 {
        1.0 / (1.0 + (-x).exp())
    }

    // Прямой проход
    fn forward(&self, features: &[f64]) -> f64 {
        let mut sum = self.bias;
        for (i, &f) in features.iter().enumerate() {
            if i < self.weights.len() {
                sum += self.weights[i] * f;
            }
        }
        Self::sigmoid(sum)
    }

    // Функция потерь (binary cross-entropy)
    fn loss(&self, predictions: &[f64], targets: &[f64]) -> f64 {
        let mut loss = 0.0;
        for (&pred, &target) in predictions.iter().zip(targets.iter()) {
            let eps = 1e-7;
            let pred_clamped = pred.clamp(eps, 1.0 - eps);
            loss -= target * pred_clamped.ln() + (1.0 - target) * (1.0 - pred_clamped).ln();
        }
        loss / predictions.len() as f64
    }

    // Обучение (градиентный спуск)
    fn train(&mut self, features_list: &[Vec<f64>], targets: &[f64], epochs: usize, lr: f64) {
        println!("Training classifier on {} samples...", features_list.len());

        for epoch in 0..epochs {
            let mut total_loss = 0.0;
            let mut grad_weights = vec![0.0; self.weights.len()];
            let mut grad_bias = 0.0;

            for (features, &target) in features_list.iter().zip(targets.iter()) {
                let pred = self.forward(features);
                let error = pred - target;

                // Градиенты
                for (i, &f) in features.iter().enumerate() {
                    if i < grad_weights.len() {
                        grad_weights[i] += error * f;
                    }
                }
                grad_bias += error;
                total_loss += (pred - target).powi(2);
            }

            // Обновление весов
            let n = features_list.len() as f64;
            for i in 0..self.weights.len() {
                self.weights[i] -= lr * grad_weights[i] / n;
            }
            self.bias -= lr * grad_bias / n;

            if epoch % 10 == 0 {
                let avg_loss = total_loss / n;
                println!("  Epoch {}: loss = {:.6}", epoch, avg_loss);
            }
        }
    }

    // Точность
    fn accuracy(&self, features_list: &[Vec<f64>], targets: &[f64], threshold: f64) -> f64 {
        let correct = features_list.iter().zip(targets.iter())
            .filter(|(feat, &target)| {
                let pred = self.forward(feat);
                (pred > threshold && target > 0.5) || (pred <= threshold && target <= 0.5)
            })
            .count();
        correct as f64 / features_list.len() as f64
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting LSTM training...");

    let data_path = Path::new("data/lstm_training.json");
    if !data_path.exists() {
        println!("❌ Training data not found. Run `cargo run --example generate_training_data` first.");
        return Ok(());
    }

    let content = fs::read_to_string(data_path)?;
    let samples: Vec<TrainingSample> = serde_json::from_str(&content)?;

    println!("📊 Loaded {} samples", samples.len());

    let mut rng = rand::thread_rng();
    let mut paired: Vec<(Vec<f64>, f64, Option<String>)> = samples
        .iter()
        .map(|s| {
            (
                sequence_to_features(&s.sequence),
                s.label,
                s.attack_type.clone(),
            )
        })
        .collect();
    paired.shuffle(&mut rng);

    println!("Extracting features from sequences (shuffled train/test split)...");

    let split_idx = (paired.len() as f64 * 0.8) as usize;
    let (train_part, test_part) = paired.split_at(split_idx);

    let train_features: Vec<Vec<f64>> = train_part.iter().map(|p| p.0.clone()).collect();
    let train_labels: Vec<f64> = train_part.iter().map(|p| p.1).collect();
    let test_features: Vec<Vec<f64>> = test_part.iter().map(|p| p.0.clone()).collect();
    let test_labels: Vec<f64> = test_part.iter().map(|p| p.1).collect();

    let feature_size = train_features[0].len();
    println!("  Feature vector size: {}", feature_size);

    println!("Train samples: {}, Test samples: {}", train_features.len(), test_features.len());

    // Создаём и обучаем классификатор
    let mut classifier = SimpleClassifier::new(feature_size);
    classifier.train(&train_features, &train_labels, 100, 0.1);

    // Оценка точности
    let train_acc = classifier.accuracy(&train_features, &train_labels, 0.5);
    let test_acc = classifier.accuracy(&test_features, &test_labels, 0.5);

    println!("\n✅ Training completed!");
    println!("  Train accuracy: {:.2}%", train_acc * 100.0);
    println!("  Test accuracy: {:.2}%", test_acc * 100.0);

    // Сохраняем модель
    let model_path = "data/lstm_model.json";
    let model_json = serde_json::json!({
        "weights": classifier.weights.as_slice(),
        "bias": classifier.bias,
        "feature_size": feature_size,
    });

    fs::write(model_path, serde_json::to_string_pretty(&model_json)?)?;
    println!("  Model saved to: {}", model_path);

    // Пример предсказания
    println!("\n📝 Example predictions:");
    for i in 0..5.min(test_features.len()) {
        let pred = classifier.forward(&test_features[i]);
        let true_label = test_labels[i];
        let attack_type = test_part[i].2.as_deref().unwrap_or("normal");
        println!(
            "  Sample {}: predicted={:.3}, true={}, type={}",
            i + 1,
            pred,
            if true_label > 0.5 { "anomaly" } else { "normal" },
            attack_type
        );
    }

    Ok(())
}
