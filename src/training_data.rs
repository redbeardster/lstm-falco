//! Load unified training datasets for LSTM (`training_data.json`).

use crate::falco_timestep::LSTM_TIMESTEP_SIZE;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct TrainingSampleFile {
    #[serde(default)]
    timestep: Option<Vec<f64>>,
    #[serde(default)]
    features: Option<Vec<f64>>,
    label: f64,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    rule: Option<String>,
}

pub struct LoadedTrainingData {
    pub timesteps: Vec<Vec<f64>>,
    pub labels: Vec<f64>,
}

pub fn load_training_data_file(path: &Path) -> Result<LoadedTrainingData> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read training data {:?}", path))?;
    parse_training_data_json(&content)
}

pub fn parse_training_data_json(content: &str) -> Result<LoadedTrainingData> {
    let samples: Vec<TrainingSampleFile> =
        serde_json::from_str(content).context("parse training data JSON array")?;

    let mut timesteps = Vec::with_capacity(samples.len());
    let mut labels = Vec::with_capacity(samples.len());

    for (idx, sample) in samples.into_iter().enumerate() {
        let vec = sample
            .timestep
            .or(sample.features)
            .ok_or_else(|| anyhow::anyhow!("sample {}: missing 'timestep' or 'features'", idx))?;

        if vec.len() != LSTM_TIMESTEP_SIZE {
            bail!(
                "sample {}: expected {}-D timestep, got {} (rule={:?})",
                idx,
                LSTM_TIMESTEP_SIZE,
                vec.len(),
                sample.rule
            );
        }

        timesteps.push(vec);
        labels.push(sample.label.clamp(0.0, 1.0));
    }

    Ok(LoadedTrainingData { timesteps, labels })
}
