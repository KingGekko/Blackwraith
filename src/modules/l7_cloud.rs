// Unauthenticated cloud asset discovery
// Bucket brute-force, storage endpoint scanning

use crate::error::Result;
use crate::core::proxy::ProxyManager;
use serde::{Serialize, Deserialize};
use reqwest::Client;
use std::collections::HashSet;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CloudAssets {
    pub aws_buckets: Vec<String>,
    pub azure_blobs: Vec<String>,
    pub gcp_buckets: Vec<String>,
    pub digitalocean_spaces: Vec<String>,
    pub alibaba_oss: Vec<String>,
}

pub async fn enumerate_cloud(domain: &str, proxy: &ProxyManager) -> Result<CloudAssets> {
    let client = proxy.build_http_client()?;
    let mut assets = CloudAssets::default();

    // 1. AWS S3 – permutations of domain and common prefixes
    let base_names = generate_bucket_names(domain);
    for name in &base_names {
        let url = format!("https://{}.s3.amazonaws.com", name);
        if client.head(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            assets.aws_buckets.push(url);
        }
    }

    // 2. Azure Blob Storage
    let storage_names = generate_storage_names(domain);
    for name in &storage_names {
        let url = format!("https://{}.blob.core.windows.net", name);
        if client.head(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            assets.azure_blobs.push(url);
        }
    }

    // 3. GCP Cloud Storage
    let gcp_names = generate_gcp_buckets(domain);
    for name in &gcp_names {
        let url = format!("https://storage.googleapis.com/{}", name);
        if client.head(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            assets.gcp_buckets.push(url);
        }
    }

    Ok(assets)
}

fn generate_bucket_names(domain: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    let base = domain.split('.').next().unwrap_or(domain);
    names.insert(base.to_string());
    names.insert(format!("{}-backup", base));
    names.insert(format!("{}-assets", base));
    names.insert(format!("{}-static", base));
    names.insert(format!("{}-media", base));
    names
}

fn generate_storage_names(domain: &str) -> HashSet<String> {
    generate_bucket_names(domain) // similar
}

fn generate_gcp_buckets(domain: &str) -> HashSet<String> {
    generate_bucket_names(domain)
}