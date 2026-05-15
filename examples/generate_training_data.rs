// examples/generate_training_data.rs

use rand::Rng;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
pub struct TrainingSample {
    pub sequence: Vec<Vec<f64>>,
    pub label: f64,
    pub attack_type: Option<String>,
}

pub struct DataGenerator {
    rng: rand::rngs::ThreadRng,
}

impl DataGenerator {
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    // Нормальная последовательность
    fn normal_sequence(&mut self, seq_length: usize, feature_size: usize) -> Vec<Vec<f64>> {
        let mut seq = Vec::with_capacity(seq_length);
        for _ in 0..seq_length {
            let mut features = vec![0.0; feature_size];
            features[0] = self.rng.gen_range(10.0..100.0);  // read
            features[1] = self.rng.gen_range(5.0..50.0);   // write
            features[2] = self.rng.gen_range(1.0..20.0);   // close
            features[3] = self.rng.gen_range(0.0..5.0);    // socket
            features[4] = self.rng.gen_range(0.0..3.0);    // connect
            features[5] = self.rng.gen_range(0.0..2.0);    // execve (редко)
            features[6] = self.rng.gen_range(10.0..100.0); // интервал
            features[7] = self.rng.gen_range(1.0..3.0);    // приоритет
            seq.push(features);
        }
        seq
    }

    // Reverse Shell атака
    fn reverse_shell(&mut self, seq_length: usize, feature_size: usize) -> Vec<Vec<f64>> {
        let mut seq = Vec::with_capacity(seq_length);
        for i in 0..seq_length {
            let mut features = vec![0.0; feature_size];
            if i < seq_length / 3 {
                // Подготовка
                features[5] = self.rng.gen_range(1.0..3.0);   // execve
            } else if i < 2 * seq_length / 3 {
                // Соединение
                features[3] = self.rng.gen_range(5.0..15.0);  // socket
                features[4] = self.rng.gen_range(3.0..10.0);  // connect
                features[7] = 4.0;                            // высокий приоритет
            } else {
                // Шелл
                features[1] = self.rng.gen_range(30.0..100.0); // write
                features[5] = self.rng.gen_range(1.0..2.0);    // execve
                features[7] = 5.0;                             // критический
            }
            features[6] = self.rng.gen_range(10.0..50.0);
            seq.push(features);
        }
        seq
    }

    // Криптомайнер
    fn cryptominer(&mut self, seq_length: usize, feature_size: usize) -> Vec<Vec<f64>> {
        let mut seq = Vec::with_capacity(seq_length);
        for _ in 0..seq_length {
            let mut features = vec![0.0; feature_size];
            features[0] = self.rng.gen_range(50.0..200.0);   // read
            features[1] = self.rng.gen_range(30.0..150.0);   // write
            features[3] = self.rng.gen_range(1.0..5.0);      // socket
            features[4] = self.rng.gen_range(1.0..5.0);      // connect
            features[6] = self.rng.gen_range(50.0..200.0);   // интервал
            seq.push(features);
        }
        seq
    }

    // Lateral Movement
    fn lateral_movement(&mut self, seq_length: usize, feature_size: usize) -> Vec<Vec<f64>> {
        let mut seq = Vec::with_capacity(seq_length);
        for i in 0..seq_length {
            let mut features = vec![0.0; feature_size];
            if i < seq_length / 2 {
                features[3] = self.rng.gen_range(1.0..5.0);   // socket
                features[4] = self.rng.gen_range(1.0..5.0);   // connect
            } else {
                features[5] = self.rng.gen_range(1.0..2.0);   // execve
            }
            features[6] = self.rng.gen_range(10.0..100.0);
            features[7] = self.rng.gen_range(3.0..5.0);       // высокий приоритет
            seq.push(features);
        }
        seq
    }

    pub fn generate(&mut self, samples_per_type: usize, seq_length: usize, feature_size: usize) -> Vec<TrainingSample> {
        let mut all = Vec::new();

        // Нормальные
        for _ in 0..samples_per_type {
            all.push(TrainingSample {
                sequence: self.normal_sequence(seq_length, feature_size),
                label: 0.0,
                attack_type: None,
            });
        }

        // Reverse Shell
        for _ in 0..samples_per_type {
            all.push(TrainingSample {
                sequence: self.reverse_shell(seq_length, feature_size),
                label: 1.0,
                attack_type: Some("reverse_shell".to_string()),
            });
        }

        // Cryptominer
        for _ in 0..samples_per_type {
            all.push(TrainingSample {
                sequence: self.cryptominer(seq_length, feature_size),
                label: 1.0,
                attack_type: Some("cryptominer".to_string()),
            });
        }

        // Lateral Movement
        for _ in 0..samples_per_type {
            all.push(TrainingSample {
                sequence: self.lateral_movement(seq_length, feature_size),
                label: 1.0,
                attack_type: Some("lateral_movement".to_string()),
            });
        }

        all
    }

    pub fn save(&self, samples: &[TrainingSample], path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(samples)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        println!("✅ Saved {} samples to {}", samples.len(), path);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Generating training data for LSTM...");

    let mut generator = DataGenerator::new();
    let samples = generator.generate(500, 20, 8);

    generator.save(&samples, "data/lstm_training.json")?;

    let normal = samples.iter().filter(|s| s.label == 0.0).count();
    let anomalies = samples.iter().filter(|s| s.label == 1.0).count();

    println!("  Normal: {}", normal);
    println!("  Anomalies: {}", anomalies);
    println!("  Total: {}", samples.len());

    Ok(())
}
