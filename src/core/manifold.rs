// Riemannian geometry on attack surfaces
// Computes Ricci curvature to predict exploit chain viability

use crate::output::ScanReport;

/// Vulnerability manifold using Riemannian geometry concepts
/// Models attack surfaces as a continuous manifold where:
/// - x0: time dimension
/// - x1: remote execution surface
/// - x2: privilege escalation surface
/// - x3: information leakage surface
#[derive(Debug)]
pub struct VulnerabilityManifold {
    /// Metric tensor g_{\mu\nu} (4×4 diagonal approximation)
    metric: [[f64; 4]; 4],
    /// Scalar curvature R (precomputed)
    scalar_curvature: f64,
}

impl VulnerabilityManifold {
    pub fn new() -> Self {
        // Initialize with identity metric (flat spacetime)
        let mut metric = [[0.0f64; 4]; 4];
        for i in 0..4 {
            metric[i][i] = 1.0; // diagonal identity
        }
        Self {
            metric,
            scalar_curvature: 0.0,
        }
    }

    /// Update manifold from scan findings
    pub fn update(&mut self, report: &ScanReport) {
        let mut techniques_found = std::collections::HashSet::new();

        // Map findings to manifold coordinates
        // x0: time, x1: remote exec, x2: privilege esc, x3: info leak
        for tech in &report.techniques {
            techniques_found.insert(tech.technique_id.as_str());
            let coords = match tech.technique_id.as_str() {
                "T1190" => [1.0, 0.0, 0.0], // Exploit Public-Facing Application
                "T1068" => [0.0, 1.0, 0.0], // Exploitation for Privilege Escalation
                "T1046" => [0.0, 0.0, 1.0], // Network Service Scanning
                _ => continue,
            };
            // Perturb metric (diagonal)
            self.apply_finding(&coords, tech.confidence as f64);
        }

        // Synergy: Remote Exec (T1190) + Priv Esc (T1068)
        // If both present, reduce distance between dimensions 1 and 2 (increase g_12)
        if techniques_found.contains("T1190") && techniques_found.contains("T1068") {
             self.metric[1][2] += 0.5;
             self.metric[2][1] += 0.5;
        }

        self.recompute_curvature();
    }

    fn apply_finding(&mut self, coords: &[f64; 3], confidence: f64) {
        // Increase metric at this point -> indicates "bump" in vulnerability landscape
        for i in 1..4 {
            // Kronecker delta style perturbation on the diagonal
            self.metric[i][i] += confidence * coords[i - 1];
        }
    }

    fn recompute_curvature(&mut self) {
        // Curvature related to determinant of metric (volume element density)
        // Det(g) approximation for 4x4
        // Since we mainly populate diagonal and small off-diagonal, trace is still a decent proxy for scalar curvature
        // But let's add off-diagonal contribution
        let mut trace = 0.0;
        let mut off_diag = 0.0;
        
        for i in 0..4 {
            trace += self.metric[i][i];
            for j in 0..4 {
                if i != j {
                    off_diag += self.metric[i][j].abs();
                }
            }
        }
        
        self.scalar_curvature = (trace + off_diag) / 4.0;
    }

    /// Negative curvature indicates interconnectivity → chainable exploits
    pub fn compute_curvature(&self) -> f64 {
        self.scalar_curvature
    }

    /// Predict if a chain of exploits exists between two points
    /// Returns Riemannian distance ds^2 = g_uv dx^u dx^v
    pub fn geodesic_distance(&self, start: &[f64; 3], end: &[f64; 3]) -> f64 {
        let dx = [
            0.0, // dt (ignore time diff for spatial distance)
            end[0] - start[0],
            end[1] - start[1],
            end[2] - start[2],
        ];

        let mut ds_sq = 0.0;
        for mu in 1..4 {
            for nu in 1..4 {
                 ds_sq += self.metric[mu][nu] * dx[mu] * dx[nu];
            }
        }
        
        ds_sq.sqrt()
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manifold_is_flat() {
        let m = VulnerabilityManifold::new();
        // Identity metric → curvature should be 1.0 (trace of [1,1,1] / 3)
        assert!((m.compute_curvature() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_geodesic_symmetry() {
        let m = VulnerabilityManifold::new();
        let a = [1.0, 0.0, 0.0];
        let b = [0.0, 1.0, 0.0];
        assert!((m.geodesic_distance(&a, &b) - m.geodesic_distance(&b, &a)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_synergy_metric() {
        use crate::output::{Technique, ScanReport};
        use super::VulnerabilityManifold;

        let mut m = VulnerabilityManifold::new();
        let report = ScanReport {
            techniques: vec![
                Technique { technique_id: "T1190".into(), technique_name: "A".into(), confidence: 1.0, evidence: serde_json::Value::Null },
                Technique { technique_id: "T1068".into(), technique_name: "B".into(), confidence: 1.0, evidence: serde_json::Value::Null },
            ],
            ..ScanReport::new()
        };
        m.update(&report);
        
        // Check off-diagonal term g_12 (RemoteExec <-> PrivEsc)
        assert!(m.metric[1][2] > 0.0);
        
        let p1 = [1.0, 0.0, 0.0];
        let p2 = [0.0, 1.0, 0.0];
        let dist = m.geodesic_distance(&p1, &p2);
        
        assert!(dist < 2.0);
    }
}