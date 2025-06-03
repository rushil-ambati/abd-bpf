//! Utility Functions Module
//!
//! This module provides common utility functions used across the benchmark library,
//! including statistics calculations, file I/O operations, and data processing helpers.
//!
//! ## Features
//!
//! - **Statistical Analysis**: Calculate averages, percentiles, and other statistics
//! - **File Operations**: Save and load benchmark results in JSON format
//! - **Data Processing**: Helper functions for data manipulation and validation
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use abd_benchmark::utils::{calculate_average, calculate_percentile, save_json_results};
//!
//! let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
//! let avg = calculate_average(&data);
//! let p95 = calculate_percentile(&data, 95.0);
//! ```

use std::{fs::File, io::Write};

use serde::Serialize;

use crate::types::{BenchmarkError, BenchmarkResult};

/// Calculates the arithmetic mean of a vector of values
///
/// # Arguments
///
/// * `values` - A slice of floating point values
///
/// # Returns
///
/// Returns the average value, or 0.0 if the slice is empty
///
/// # Example
///
/// ```rust
/// use abd_benchmark::utils::calculate_average;
///
/// let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
/// let avg = calculate_average(&data);
/// assert_eq!(avg, 3.0);
/// ```
pub fn calculate_average(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

/// Calculates a specific percentile of a vector of values
///
/// Uses the nearest-rank method for percentile calculation.
///
/// # Arguments
///
/// * `values` - A slice of floating point values
/// * `percentile` - The percentile to calculate (0.0 to 100.0)
///
/// # Returns
///
/// Returns the percentile value, or 0.0 if the slice is empty
///
/// # Example
///
/// ```rust
/// use abd_benchmark::utils::calculate_percentile;
///
/// let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
/// let p50 = calculate_percentile(&data, 50.0);
/// let p95 = calculate_percentile(&data, 95.0);
/// ```
pub fn calculate_percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let len = sorted.len();
    let idx_f = percentile / 100.0 * (len - 1) as f64;
    let index = idx_f.round() as usize;

    sorted[index.min(len - 1)]
}

/// Saves any serializable data structure to a JSON file
///
/// This is a generic function that can save any type that implements Serialize.
///
/// # Arguments
///
/// * `data` - The data structure to save
/// * `filename` - The path to the output file
///
/// # Returns
///
/// Returns Ok(()) on success, or a BenchmarkError on failure
///
/// # Errors
///
/// This function will return an error if:
/// - The data cannot be serialized to JSON
/// - The file cannot be created or written to
/// - File system permissions prevent writing
///
/// # Example
///
/// ```rust,no_run
/// use abd_benchmark::utils::save_json_results;
/// use abd_benchmark::LatencyResults;
///
/// let results = LatencyResults::default();
/// save_json_results(&results, "results.json")?;
/// ```
pub fn save_json_results<T: Serialize>(data: &T, filename: &str) -> BenchmarkResult<()> {
    let json = serde_json::to_string_pretty(data).map_err(|e| BenchmarkError::Json(e))?;

    let mut file = File::create(filename).map_err(|e| BenchmarkError::Io(e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| BenchmarkError::Io(e))?;

    log::info!("Results saved to {}", filename);
    Ok(())
}

/// Validates that a percentile value is within valid range
///
/// # Arguments
///
/// * `percentile` - The percentile value to validate
///
/// # Returns
///
/// Returns true if the percentile is between 0.0 and 100.0 (inclusive)
pub fn is_valid_percentile(percentile: f64) -> bool {
    percentile >= 0.0 && percentile <= 100.0
}

/// Formats a duration in microseconds to a human-readable string
///
/// # Arguments
///
/// * `microseconds` - Duration in microseconds
///
/// # Returns
///
/// Returns a formatted string with appropriate units
pub fn format_duration(microseconds: f64) -> String {
    if microseconds < 1000.0 {
        format!("{:.2}μs", microseconds)
    } else if microseconds < 1_000_000.0 {
        format!("{:.2}ms", microseconds / 1000.0)
    } else {
        format!("{:.2}s", microseconds / 1_000_000.0)
    }
}

/// Calculates basic statistics for a dataset
///
/// # Arguments
///
/// * `values` - The dataset to analyze
///
/// # Returns
///
/// Returns a tuple of (min, max, mean, median, std_dev)
pub fn calculate_basic_stats(values: &[f64]) -> (f64, f64, f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0, 0.0, 0.0);
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let mean = calculate_average(values);
    let median = calculate_percentile(values, 50.0);

    // Calculate standard deviation
    let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;
    let std_dev = variance.sqrt();

    (min, max, mean, median, std_dev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_average() {
        assert_eq!(calculate_average(&[]), 0.0);
        assert_eq!(calculate_average(&[1.0]), 1.0);
        assert_eq!(calculate_average(&[1.0, 2.0, 3.0]), 2.0);
        assert_eq!(calculate_average(&[1.0, 2.0, 3.0, 4.0, 5.0]), 3.0);
    }

    #[test]
    fn test_calculate_percentile() {
        assert_eq!(calculate_percentile(&[], 50.0), 0.0);
        assert_eq!(calculate_percentile(&[1.0], 50.0), 1.0);

        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(calculate_percentile(&data, 0.0), 1.0);
        assert_eq!(calculate_percentile(&data, 50.0), 3.0);
        assert_eq!(calculate_percentile(&data, 100.0), 5.0);
    }

    #[test]
    fn test_is_valid_percentile() {
        assert!(is_valid_percentile(0.0));
        assert!(is_valid_percentile(50.0));
        assert!(is_valid_percentile(100.0));
        assert!(!is_valid_percentile(-1.0));
        assert!(!is_valid_percentile(101.0));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500.0), "500.00μs");
        assert_eq!(format_duration(1500.0), "1.50ms");
        assert_eq!(format_duration(1_500_000.0), "1.50s");
    }
}
