//! Backpropagation Through Time для LSTM-ячейки + сигмоидного классификатора.

use crate::ml::lstm_cell::LSTMCell;
use crate::ml::lstm_online::{predict_hidden, LSTMClassifierState};
use ndarray::{Array1, Array2, Axis};

/// Кэш одного шага forward (для backward).
#[derive(Clone)]
pub struct StepCache {
    pub x: Array1<f64>,
    pub h_prev: Array1<f64>,
    pub c_prev: Array1<f64>,
    pub i: Array1<f64>,
    pub f: Array1<f64>,
    pub c_tilde: Array1<f64>,
    pub c: Array1<f64>,
    pub o: Array1<f64>,
    pub h: Array1<f64>,
}

/// Накопленные градиенты по весам LSTM.
#[derive(Clone)]
pub struct LSTMGradients {
    pub w_ix: Array2<f64>,
    pub w_hx: Array2<f64>,
    pub b_i: Array1<f64>,
    pub w_fx: Array2<f64>,
    pub w_hx_f: Array2<f64>,
    pub b_f: Array1<f64>,
    pub w_ox: Array2<f64>,
    pub w_hx_o: Array2<f64>,
    pub b_o: Array1<f64>,
    pub w_cx: Array2<f64>,
    pub w_hx_c: Array2<f64>,
    pub b_c: Array1<f64>,
}

impl LSTMGradients {
    pub fn zeros(cell: &LSTMCell) -> Self {
        let z2 = |r: usize, c: usize| Array2::zeros((r, c));
        let z1 = |n: usize| Array1::zeros(n);
        let h = cell.hidden_size();
        let x = cell.input_size();
        Self {
            w_ix: z2(h, x),
            w_hx: z2(h, h),
            b_i: z1(h),
            w_fx: z2(h, x),
            w_hx_f: z2(h, h),
            b_f: z1(h),
            w_ox: z2(h, x),
            w_hx_o: z2(h, h),
            b_o: z1(h),
            w_cx: z2(h, x),
            w_hx_c: z2(h, h),
            b_c: z1(h),
        }
    }

    pub fn clip_global_norm(&mut self, max_norm: f64) {
        let mut sum_sq: f64 = 0.0;
        for g in [
            &self.w_ix,
            &self.w_hx,
            &self.w_fx,
            &self.w_hx_f,
            &self.w_ox,
            &self.w_hx_o,
            &self.w_cx,
            &self.w_hx_c,
        ] {
            for &v in g.iter() {
                sum_sq += v * v;
            }
        }
        for b in [&self.b_i, &self.b_f, &self.b_o, &self.b_c] {
            for &v in b.iter() {
                sum_sq += v * v;
            }
        }
        let norm = sum_sq.sqrt();
        if norm > max_norm && norm > 1e-12 {
            let scale = max_norm / norm;
            self.scale(scale);
        }
    }

    fn scale(&mut self, s: f64) {
        self.w_ix *= s;
        self.w_hx *= s;
        self.b_i *= s;
        self.w_fx *= s;
        self.w_hx_f *= s;
        self.b_f *= s;
        self.w_ox *= s;
        self.w_hx_o *= s;
        self.b_o *= s;
        self.w_cx *= s;
        self.w_hx_c *= s;
        self.b_c *= s;
    }
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

fn tanh(x: f64) -> f64 {
    x.tanh()
}

fn outer_add(grad: &mut Array2<f64>, a: &Array1<f64>, b: &Array1<f64>) {
    let outer = a.view().insert_axis(Axis(1)).dot(&b.view().insert_axis(Axis(0)));
    *grad = &*grad + &outer;
}

impl LSTMCell {
    /// Forward с сохранением промежуточных активаций.
    pub fn forward_cached(
        &self,
        x: &Array1<f64>,
        h_prev: &Array1<f64>,
        c_prev: &Array1<f64>,
    ) -> StepCache {
        let i_gate = (&self.w_ix.dot(x) + &self.w_hx.dot(h_prev) + &self.b_i).mapv(sigmoid);
        let f_gate = (&self.w_fx.dot(x) + &self.w_hx_f.dot(h_prev) + &self.b_f).mapv(sigmoid);
        let c_tilde = (&self.w_cx.dot(x) + &self.w_hx_c.dot(h_prev) + &self.b_c).mapv(tanh);
        let c_t = &i_gate * &c_tilde + &f_gate * c_prev;
        let o_gate = (&self.w_ox.dot(x) + &self.w_hx_o.dot(h_prev) + &self.b_o).mapv(sigmoid);
        let h_t = &o_gate * &c_t.mapv(tanh);

        StepCache {
            x: x.clone(),
            h_prev: h_prev.clone(),
            c_prev: c_prev.clone(),
            i: i_gate,
            f: f_gate,
            c_tilde,
            c: c_t,
            o: o_gate,
            h: h_t,
        }
    }

    /// Один шаг backward: возвращает градиенты по h_prev и c_prev.
    pub fn backward_step(
        &self,
        cache: &StepCache,
        dh: &Array1<f64>,
        dc_future: &Array1<f64>,
        grads: &mut LSTMGradients,
    ) -> (Array1<f64>, Array1<f64>) {
        let tanh_c: Array1<f64> = cache.c.mapv(tanh);
        let tanh_c_deriv: Array1<f64> = cache.c.mapv(|c| 1.0 - tanh(c).powi(2));

        // h = o ⊙ tanh(c)
        let dc = dh * &cache.o * &tanh_c_deriv + dc_future;
        let do_gate = dh * &tanh_c;

        // c = i⊙g + f⊙c_prev
        let di = &dc * &cache.c_tilde;
        let dg = &dc * &cache.i;
        let df = &dc * &cache.c_prev;
        let dc_prev = &dc * &cache.f;

        let di_pre = di * &cache.i.mapv(|v| v * (1.0 - v));
        let df_pre = df * &cache.f.mapv(|v| v * (1.0 - v));
        let dg_pre = dg * &cache.c_tilde.mapv(|v| 1.0 - v * v);
        let do_pre = do_gate * &cache.o.mapv(|v| v * (1.0 - v));

        outer_add(&mut grads.w_ix, &di_pre, &cache.x);
        outer_add(&mut grads.w_hx, &di_pre, &cache.h_prev);
        grads.b_i += &di_pre;

        outer_add(&mut grads.w_fx, &df_pre, &cache.x);
        outer_add(&mut grads.w_hx_f, &df_pre, &cache.h_prev);
        grads.b_f += &df_pre;

        outer_add(&mut grads.w_cx, &dg_pre, &cache.x);
        outer_add(&mut grads.w_hx_c, &dg_pre, &cache.h_prev);
        grads.b_c += &dg_pre;

        outer_add(&mut grads.w_ox, &do_pre, &cache.x);
        outer_add(&mut grads.w_hx_o, &do_pre, &cache.h_prev);
        grads.b_o += &do_pre;

        let dh_prev = self.w_hx.t().dot(&di_pre)
            + self.w_hx_f.t().dot(&df_pre)
            + self.w_hx_c.t().dot(&dg_pre)
            + self.w_hx_o.t().dot(&do_pre);

        (dh_prev, dc_prev)
    }

    pub fn apply_gradients(&mut self, grads: &LSTMGradients, lr: f64) {
        let neg = -lr;
        self.w_ix.scaled_add(neg, &grads.w_ix);
        self.w_hx.scaled_add(neg, &grads.w_hx);
        self.b_i.scaled_add(neg, &grads.b_i);
        self.w_fx.scaled_add(neg, &grads.w_fx);
        self.w_hx_f.scaled_add(neg, &grads.w_hx_f);
        self.b_f.scaled_add(neg, &grads.b_f);
        self.w_ox.scaled_add(neg, &grads.w_ox);
        self.w_hx_o.scaled_add(neg, &grads.w_hx_o);
        self.b_o.scaled_add(neg, &grads.b_o);
        self.w_cx.scaled_add(neg, &grads.w_cx);
        self.w_hx_c.scaled_add(neg, &grads.w_hx_c);
        self.b_c.scaled_add(neg, &grads.b_c);
    }
}

/// Градиент loss по hidden (MSE + сигмоид): L = 0.5 (ŷ - y)², ŷ = σ(w·h + b).
fn classifier_grad_h(
    classifier: &LSTMClassifierState,
    hidden: &[f64],
    pred: f64,
    label: f64,
) -> Array1<f64> {
    let n = classifier.weights.len().min(hidden.len());
    let dz = (pred - label) * pred * (1.0 - pred);
    let mut dh = Array1::zeros(classifier.hidden_size);
    for i in 0..n {
        dh[i] = dz * classifier.weights[i];
    }
    dh
}

fn update_classifier(
    classifier: &mut LSTMClassifierState,
    hidden: &[f64],
    pred: f64,
    label: f64,
    lr: f64,
) {
    let n = classifier.weights.len().min(hidden.len());
    let dz = (pred - label) * pred * (1.0 - pred);
    for i in 0..n {
        classifier.weights[i] -= lr * dz * hidden[i];
    }
    classifier.bias -= lr * dz;
}

/// Полный BPTT по последовательности; возвращает loss.
pub fn train_sequence_bptt(
    cell: &mut LSTMCell,
    classifier: &mut LSTMClassifierState,
    sequence: &[Vec<f64>],
    label: f64,
    lr: f64,
    grad_clip: f64,
) -> f64 {
    if sequence.is_empty() {
        return 0.0;
    }

    let h_dim = cell.hidden_size();
    let mut h = Array1::zeros(h_dim);
    let mut c = Array1::zeros(h_dim);
    let mut caches = Vec::with_capacity(sequence.len());

    for step in sequence {
        if step.len() != cell.input_size() {
            continue;
        }
        let x = Array1::from_vec(step.clone());
        let cache = cell.forward_cached(&x, &h, &c);
        h = cache.h.clone();
        c = cache.c.clone();
        caches.push(cache);
    }

    if caches.is_empty() {
        return 0.0;
    }

    let hidden: Vec<f64> = h.iter().copied().collect();
    let pred = predict_hidden(classifier, &hidden);
    let loss = 0.5 * (pred - label).powi(2);

    let mut dh = classifier_grad_h(classifier, &hidden, pred, label);
    let mut dc = Array1::zeros(h_dim);
    let mut grads = LSTMGradients::zeros(cell);

    for cache in caches.iter().rev() {
        let (dh_prev, dc_prev) = cell.backward_step(cache, &dh, &dc, &mut grads);
        dh = dh_prev;
        dc = dc_prev;
    }

    grads.clip_global_norm(grad_clip);
    cell.apply_gradients(&grads, lr);
    update_classifier(classifier, &hidden, pred, label, lr);

    loss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml::lstm_cell::LSTMCell;

    fn make_sequence(n: usize, label_high: bool) -> (Vec<Vec<f64>>, f64) {
        let mut seq = Vec::with_capacity(n);
        for t in 0..n {
            let mut x = vec![0.1; 8];
            if label_high {
                x[0] = 4.0 + 0.01 * t as f64;
                x[3] = 1.0;
            } else {
                x[0] = 1.0;
                x[3] = 0.1;
            }
            seq.push(x);
        }
        let label = if label_high { 1.0 } else { 0.0 };
        (seq, label)
    }

    #[test]
    fn bptt_loss_decreases() {
        let mut cell = LSTMCell::new(8, 16);
        let mut clf = LSTMClassifierState {
            weights: vec![0.01; 16],
            bias: 0.0,
            hidden_size: 16,
        };
        let (seq, label) = make_sequence(6, true);

        let loss0 = {
            let h = forward_last_hidden(&cell, &seq);
            let p = predict_hidden(&clf, &h);
            0.5 * (p - label).powi(2)
        };

        for _ in 0..40 {
            train_sequence_bptt(&mut cell, &mut clf, &seq, label, 0.05, 5.0);
        }

        let loss1 = {
            let h = forward_last_hidden(&cell, &seq);
            let p = predict_hidden(&clf, &h);
            0.5 * (p - label).powi(2)
        };

        assert!(
            loss1 < loss0,
            "BPTT should reduce loss: before={loss0}, after={loss1}"
        );
    }

    fn forward_last_hidden(cell: &LSTMCell, sequence: &[Vec<f64>]) -> Vec<f64> {
        let mut h = Array1::zeros(cell.hidden_size());
        let mut c = Array1::zeros(cell.hidden_size());
        for step in sequence {
            let x = Array1::from_vec(step.clone());
            let cache = cell.forward_cached(&x, &h, &c);
            h = cache.h;
            c = cache.c;
        }
        h.iter().copied().collect()
    }
}
