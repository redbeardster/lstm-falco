// src/lstm_cell.rs — одна LSTM-ячейка с сериализацией весов.

use anyhow::{ensure, Result};
use ndarray::{Array1, Array2};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LSTMCellState {
    pub w_ix: Vec<Vec<f64>>,
    pub w_hx: Vec<Vec<f64>>,
    pub b_i: Vec<f64>,
    pub w_fx: Vec<Vec<f64>>,
    pub w_hx_f: Vec<Vec<f64>>,
    pub b_f: Vec<f64>,
    pub w_ox: Vec<Vec<f64>>,
    pub w_hx_o: Vec<Vec<f64>>,
    pub b_o: Vec<f64>,
    pub w_cx: Vec<Vec<f64>>,
    pub w_hx_c: Vec<Vec<f64>>,
    pub b_c: Vec<f64>,
    pub input_size: usize,
    pub hidden_size: usize,
}

pub struct LSTMCell {
    pub(crate) w_ix: Array2<f64>,
    pub(crate) w_hx: Array2<f64>,
    pub(crate) b_i: Array1<f64>,
    pub(crate) w_fx: Array2<f64>,
    pub(crate) w_hx_f: Array2<f64>,
    pub(crate) b_f: Array1<f64>,
    pub(crate) w_ox: Array2<f64>,
    pub(crate) w_hx_o: Array2<f64>,
    pub(crate) b_o: Array1<f64>,
    pub(crate) w_cx: Array2<f64>,
    pub(crate) w_hx_c: Array2<f64>,
    pub(crate) b_c: Array1<f64>,
    hidden_size: usize,
    input_size: usize,
}

fn rand_matrix(rows: usize, cols: usize, rng: &mut impl Rng) -> Array2<f64> {
    Array2::from_shape_fn((rows, cols), |_| rng.gen_range(-0.1..0.1))
}

fn array2_to_vec(m: &Array2<f64>) -> Vec<Vec<f64>> {
    (0..m.nrows())
        .map(|i| m.row(i).iter().copied().collect())
        .collect()
}

fn vec_to_array2(rows: &[Vec<f64>]) -> Result<Array2<f64>> {
    ensure!(!rows.is_empty(), "empty matrix");
    let cols = rows[0].len();
    let mut m = Array2::zeros((rows.len(), cols));
    for (i, row) in rows.iter().enumerate() {
        ensure!(row.len() == cols, "ragged matrix row {i}");
        for (j, &v) in row.iter().enumerate() {
            m[[i, j]] = v;
        }
    }
    Ok(m)
}

impl LSTMCell {
    pub fn new(input_size: usize, hidden_size: usize) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            w_ix: rand_matrix(hidden_size, input_size, &mut rng),
            w_hx: rand_matrix(hidden_size, hidden_size, &mut rng),
            b_i: Array1::zeros(hidden_size),
            w_fx: rand_matrix(hidden_size, input_size, &mut rng),
            w_hx_f: rand_matrix(hidden_size, hidden_size, &mut rng),
            b_f: Array1::zeros(hidden_size),
            w_ox: rand_matrix(hidden_size, input_size, &mut rng),
            w_hx_o: rand_matrix(hidden_size, hidden_size, &mut rng),
            b_o: Array1::zeros(hidden_size),
            w_cx: rand_matrix(hidden_size, input_size, &mut rng),
            w_hx_c: rand_matrix(hidden_size, hidden_size, &mut rng),
            b_c: Array1::zeros(hidden_size),
            hidden_size,
            input_size,
        }
    }

    pub fn input_size(&self) -> usize {
        self.input_size
    }

    pub fn hidden_size(&self) -> usize {
        self.hidden_size
    }

    pub fn to_state(&self) -> LSTMCellState {
        LSTMCellState {
            w_ix: array2_to_vec(&self.w_ix),
            w_hx: array2_to_vec(&self.w_hx),
            b_i: self.b_i.iter().copied().collect(),
            w_fx: array2_to_vec(&self.w_fx),
            w_hx_f: array2_to_vec(&self.w_hx_f),
            b_f: self.b_f.iter().copied().collect(),
            w_ox: array2_to_vec(&self.w_ox),
            w_hx_o: array2_to_vec(&self.w_hx_o),
            b_o: self.b_o.iter().copied().collect(),
            w_cx: array2_to_vec(&self.w_cx),
            w_hx_c: array2_to_vec(&self.w_hx_c),
            b_c: self.b_c.iter().copied().collect(),
            input_size: self.input_size,
            hidden_size: self.hidden_size,
        }
    }

    pub fn from_state(state: &LSTMCellState) -> Result<Self> {
        ensure!(
            state.input_size > 0 && state.hidden_size > 0,
            "invalid LSTM dimensions"
        );
        Ok(Self {
            w_ix: vec_to_array2(&state.w_ix)?,
            w_hx: vec_to_array2(&state.w_hx)?,
            b_i: Array1::from_vec(state.b_i.clone()),
            w_fx: vec_to_array2(&state.w_fx)?,
            w_hx_f: vec_to_array2(&state.w_hx_f)?,
            b_f: Array1::from_vec(state.b_f.clone()),
            w_ox: vec_to_array2(&state.w_ox)?,
            w_hx_o: vec_to_array2(&state.w_hx_o)?,
            b_o: Array1::from_vec(state.b_o.clone()),
            w_cx: vec_to_array2(&state.w_cx)?,
            w_hx_c: vec_to_array2(&state.w_hx_c)?,
            b_c: Array1::from_vec(state.b_c.clone()),
            hidden_size: state.hidden_size,
            input_size: state.input_size,
        })
    }

    pub fn forward(
        &self,
        x: &Array1<f64>,
        h_prev: &Array1<f64>,
        c_prev: &Array1<f64>,
    ) -> (Array1<f64>, Array1<f64>) {
        let i_gate = (&self.w_ix.dot(x) + &self.w_hx.dot(h_prev) + &self.b_i).mapv(Self::sigmoid);
        let f_gate = (&self.w_fx.dot(x) + &self.w_hx_f.dot(h_prev) + &self.b_f).mapv(Self::sigmoid);
        let c_tilde = (&self.w_cx.dot(x) + &self.w_hx_c.dot(h_prev) + &self.b_c).mapv(Self::tanh);
        let c_t = &i_gate * &c_tilde + &f_gate * c_prev;
        let o_gate = (&self.w_ox.dot(x) + &self.w_hx_o.dot(h_prev) + &self.b_o).mapv(Self::sigmoid);
        let h_t = &o_gate * &c_t.mapv(Self::tanh);
        (h_t, c_t)
    }

    fn sigmoid(x: f64) -> f64 {
        1.0 / (1.0 + (-x).exp())
    }

    fn tanh(x: f64) -> f64 {
        x.tanh()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip() {
        let cell = LSTMCell::new(8, 16);
        let restored = LSTMCell::from_state(&cell.to_state()).unwrap();
        assert_eq!(restored.input_size(), 8);
        assert_eq!(restored.hidden_size(), 16);
        let x = Array1::from_vec(vec![0.1; 8]);
        let h0 = Array1::zeros(16);
        let c0 = Array1::zeros(16);
        let (h1, _) = cell.forward(&x, &h0, &c0);
        let (h2, _) = restored.forward(&x, &h0, &c0);
        assert!((h1 - h2).mapv(f64::abs).sum() < 1e-9);
    }
}
