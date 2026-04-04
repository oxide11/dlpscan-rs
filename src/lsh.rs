//! Locality-Sensitive Hashing (LSH) for fuzzy document similarity detection.
//!
//! Register known sensitive documents, then query new text to find similar
//! documents above a configurable Jaccard similarity threshold.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

const LARGE_PRIME: u64 = (1u64 << 61) - 1;
const MAX_HASH: u64 = (1u64 << 32) - 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A similarity match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityMatch {
    pub doc_id: String,
    pub similarity: f64,
    pub sensitivity: String,
    #[serde(default)]
    pub doc_metadata: HashMap<String, String>,
}

/// Internal document entry.
struct DocumentEntry {
    doc_id: String,
    signature: Vec<u64>,
    sensitivity: String,
    metadata: HashMap<String, String>,
    #[allow(dead_code)]
    shingle_count: usize,
}

// ---------------------------------------------------------------------------
// DocumentVault
// ---------------------------------------------------------------------------

/// LSH-based document similarity vault.
pub struct DocumentVault {
    num_hashes: usize,
    bands: usize,
    rows_per_band: usize,
    threshold: f64,
    shingle_size: usize,
    hash_funcs: Vec<(u64, u64)>,
    documents: Mutex<HashMap<String, DocumentEntry>>,
    band_index: Mutex<Vec<HashMap<u64, HashSet<String>>>>,
}

impl DocumentVault {
    /// Create a new document vault.
    ///
    /// - `num_hashes`: MinHash signature length (must be divisible by `bands`)
    /// - `bands`: Number of LSH bands
    /// - `threshold`: Minimum Jaccard similarity (0..1]
    /// - `shingle_size`: Words per shingle
    pub fn new(num_hashes: usize, bands: usize, threshold: f64, shingle_size: usize) -> Self {
        assert!(num_hashes % bands == 0, "num_hashes must be divisible by bands");
        assert!(threshold > 0.0 && threshold <= 1.0, "threshold must be in (0, 1]");

        let rows_per_band = num_hashes / bands;
        let hash_funcs = make_hash_funcs(num_hashes, 42);
        let band_index = (0..bands).map(|_| HashMap::new()).collect();

        Self {
            num_hashes,
            bands,
            rows_per_band,
            threshold,
            shingle_size,
            hash_funcs,
            documents: Mutex::new(HashMap::new()),
            band_index: Mutex::new(band_index),
        }
    }

    /// Create with default settings (128 hashes, 16 bands, 0.8 threshold, 3-word shingles).
    pub fn default_vault() -> Self {
        Self::new(128, 16, 0.8, 3)
    }

    /// Number of registered documents.
    pub fn document_count(&self) -> usize {
        self.documents.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Register a document.
    pub fn register(
        &self,
        doc_id: &str,
        text: &str,
        sensitivity: &str,
        metadata: Option<HashMap<String, String>>,
    ) {
        let shingles = shingle(text, self.shingle_size);
        let signature = minhash(&shingles, &self.hash_funcs);

        // Add to band index
        self.add_to_index(doc_id, &signature);

        let entry = DocumentEntry {
            doc_id: doc_id.to_string(),
            signature,
            sensitivity: sensitivity.to_string(),
            metadata: metadata.unwrap_or_default(),
            shingle_count: shingles.len(),
        };

        self.documents
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(doc_id.to_string(), entry);
    }

    /// Unregister a document. Returns true if it existed.
    pub fn unregister(&self, doc_id: &str) -> bool {
        let existed = self.documents.lock().unwrap_or_else(|e| e.into_inner()).remove(doc_id).is_some();
        if existed {
            self.remove_from_index(doc_id);
        }
        existed
    }

    /// Query for similar documents. Returns matches sorted by similarity (descending).
    pub fn query(&self, text: &str, threshold: Option<f64>) -> Vec<SimilarityMatch> {
        let threshold = threshold.unwrap_or(self.threshold);
        let shingles = shingle(text, self.shingle_size);

        if shingles.is_empty() {
            return vec![];
        }

        let query_sig = minhash(&shingles, &self.hash_funcs);
        let candidates = self.get_candidates(&query_sig);

        let docs = self.documents.lock().unwrap_or_else(|e| e.into_inner());
        let mut matches: Vec<SimilarityMatch> = candidates
            .iter()
            .filter_map(|doc_id| {
                let entry = docs.get(doc_id)?;
                let sim = jaccard_from_signatures(&query_sig, &entry.signature);
                if sim >= threshold {
                    Some(SimilarityMatch {
                        doc_id: entry.doc_id.clone(),
                        similarity: sim,
                        sensitivity: entry.sensitivity.clone(),
                        doc_metadata: entry.metadata.clone(),
                    })
                } else {
                    None
                }
            })
            .collect();

        matches.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap_or(std::cmp::Ordering::Equal));
        matches
    }

    /// Fast boolean check — does any similar document exist above threshold?
    pub fn contains_similar(&self, text: &str, threshold: Option<f64>) -> bool {
        !self.query(text, threshold).is_empty()
    }

    /// Remove all documents.
    pub fn clear(&self) {
        self.documents.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let mut index = self.band_index.lock().unwrap_or_else(|e| e.into_inner());
        for band in index.iter_mut() {
            band.clear();
        }
    }

    /// Save vault to JSON file.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let docs = self.documents.lock().unwrap_or_else(|e| e.into_inner());
        let entries: Vec<serde_json::Value> = docs
            .values()
            .map(|e| {
                serde_json::json!({
                    "doc_id": e.doc_id,
                    "signature": e.signature,
                    "sensitivity": e.sensitivity,
                    "metadata": e.metadata,
                    "shingle_count": e.shingle_count,
                })
            })
            .collect();

        let data = serde_json::json!({
            "num_hashes": self.num_hashes,
            "bands": self.bands,
            "threshold": self.threshold,
            "shingle_size": self.shingle_size,
            "documents": entries,
        });

        let json = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("Failed to open {}: {}", path, e))?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(json.as_bytes()).map_err(|e| format!("Failed to write {}: {}", path, e))?;
        Ok(())
    }

    /// Load vault from JSON file.
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let data: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| e.to_string())?;

        let num_hashes = data["num_hashes"].as_u64().unwrap_or(128) as usize;
        let bands = data["bands"].as_u64().unwrap_or(16) as usize;
        let threshold = data["threshold"].as_f64().unwrap_or(0.8);
        let shingle_size = data["shingle_size"].as_u64().unwrap_or(3) as usize;

        let vault = Self::new(num_hashes, bands, threshold, shingle_size);

        if let Some(docs) = data["documents"].as_array() {
            for doc in docs {
                let doc_id = doc["doc_id"].as_str().unwrap_or("");
                let sensitivity = doc["sensitivity"].as_str().unwrap_or("sensitive");
                let signature: Vec<u64> = doc["signature"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|v| v.as_u64())
                    .collect();

                let metadata: HashMap<String, String> = doc["metadata"]
                    .as_object()
                    .map(|obj| {
                        obj.iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let shingle_count = doc["shingle_count"].as_u64().unwrap_or(0) as usize;

                vault.add_to_index(doc_id, &signature);
                vault.documents.lock().unwrap_or_else(|e| e.into_inner()).insert(
                    doc_id.to_string(),
                    DocumentEntry {
                        doc_id: doc_id.to_string(),
                        signature,
                        sensitivity: sensitivity.to_string(),
                        metadata,
                        shingle_count,
                    },
                );
            }
        }

        Ok(vault)
    }

    // -- Internal helpers --

    fn add_to_index(&self, doc_id: &str, signature: &[u64]) {
        let mut index = self.band_index.lock().unwrap_or_else(|e| e.into_inner());
        for (band_idx, chunk) in signature.chunks(self.rows_per_band).enumerate() {
            if band_idx < index.len() {
                let bucket_key = band_hash(chunk);
                index[band_idx]
                    .entry(bucket_key)
                    .or_insert_with(HashSet::new)
                    .insert(doc_id.to_string());
            }
        }
    }

    fn remove_from_index(&self, doc_id: &str) {
        let mut index = self.band_index.lock().unwrap_or_else(|e| e.into_inner());
        for band in index.iter_mut() {
            for set in band.values_mut() {
                set.remove(doc_id);
            }
        }
    }

    fn get_candidates(&self, signature: &[u64]) -> HashSet<String> {
        let index = self.band_index.lock().unwrap_or_else(|e| e.into_inner());
        let mut candidates = HashSet::new();

        for (band_idx, chunk) in signature.chunks(self.rows_per_band).enumerate() {
            if band_idx < index.len() {
                let bucket_key = band_hash(chunk);
                if let Some(docs) = index[band_idx].get(&bucket_key) {
                    candidates.extend(docs.iter().cloned());
                }
            }
        }

        candidates
    }
}

// ---------------------------------------------------------------------------
// Algorithm primitives
// ---------------------------------------------------------------------------

/// Break text into word k-grams (shingles).
fn shingle(text: &str, k: usize) -> HashSet<String> {
    let lower = text.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();

    if words.len() < k {
        // Fall back to character shingles for very short text
        let chars: Vec<char> = lower.chars().collect();
        return chars
            .windows(k.min(chars.len()).max(1))
            .map(|w| w.iter().collect::<String>())
            .collect();
    }

    words
        .windows(k)
        .map(|w| w.join(" "))
        .collect()
}

/// Generate hash function coefficients.
fn make_hash_funcs(num_hashes: usize, seed: u64) -> Vec<(u64, u64)> {
    let mut funcs = Vec::with_capacity(num_hashes);
    let mut rng_state = seed;
    for _ in 0..num_hashes {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let a = (rng_state >> 16) % LARGE_PRIME;
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let b = (rng_state >> 16) % LARGE_PRIME;
        funcs.push((a.max(1), b));
    }
    funcs
}

/// Hash a shingle string to a 32-bit integer (MD5 → truncate).
fn shingle_hash(shingle: &str) -> u64 {
    // Simple FNV-1a hash (faster than MD5, deterministic)
    let mut hash: u64 = 14695981039346656037;
    for byte in shingle.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash & MAX_HASH
}

/// Compute MinHash signature for a set of shingles.
fn minhash(shingles: &HashSet<String>, hash_funcs: &[(u64, u64)]) -> Vec<u64> {
    let shingle_hashes: Vec<u64> = shingles.iter().map(|s| shingle_hash(s)).collect();

    hash_funcs
        .iter()
        .map(|&(a, b)| {
            shingle_hashes
                .iter()
                .map(|&sh| (a.wrapping_mul(sh).wrapping_add(b)) % LARGE_PRIME % MAX_HASH)
                .min()
                .unwrap_or(MAX_HASH)
        })
        .collect()
}

/// Estimate Jaccard similarity from two MinHash signatures.
fn jaccard_from_signatures(sig1: &[u64], sig2: &[u64]) -> f64 {
    if sig1.len() != sig2.len() || sig1.is_empty() {
        return 0.0;
    }
    let matches = sig1.iter().zip(sig2.iter()).filter(|(a, b)| a == b).count();
    matches as f64 / sig1.len() as f64
}

/// Hash a band (slice of signature values) to a bucket key.
fn band_hash(band: &[u64]) -> u64 {
    let mut hash: u64 = 0;
    for &val in band {
        hash = hash.wrapping_mul(31).wrapping_add(val);
    }
    hash
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shingle() {
        let shingles = shingle("the quick brown fox jumps", 3);
        assert!(shingles.contains("the quick brown"));
        assert!(shingles.contains("quick brown fox"));
        assert!(shingles.contains("brown fox jumps"));
        assert_eq!(shingles.len(), 3);
    }

    #[test]
    fn test_minhash_deterministic() {
        let funcs = make_hash_funcs(64, 42);
        let shingles: HashSet<String> = ["hello world", "world foo"].iter().map(|s| s.to_string()).collect();
        let sig1 = minhash(&shingles, &funcs);
        let sig2 = minhash(&shingles, &funcs);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_similarity_identical() {
        let vault = DocumentVault::new(64, 8, 0.5, 3);
        vault.register("doc1", "the quick brown fox jumps over the lazy dog", "sensitive", None);

        let matches = vault.query("the quick brown fox jumps over the lazy dog", None);
        assert!(!matches.is_empty());
        assert!(matches[0].similarity > 0.9);
    }

    #[test]
    fn test_similarity_different() {
        let vault = DocumentVault::new(64, 8, 0.5, 3);
        vault.register("doc1", "the quick brown fox jumps over the lazy dog", "sensitive", None);

        let matches = vault.query("completely unrelated text about nothing similar", Some(0.5));
        assert!(matches.is_empty());
    }

    #[test]
    fn test_unregister() {
        let vault = DocumentVault::new(64, 8, 0.5, 3);
        vault.register("doc1", "test document content here for matching", "sensitive", None);
        assert_eq!(vault.document_count(), 1);
        assert!(vault.unregister("doc1"));
        assert_eq!(vault.document_count(), 0);
        assert!(!vault.unregister("doc1"));
    }

    #[test]
    fn test_jaccard_identical_signatures() {
        let sig = vec![1, 2, 3, 4, 5];
        assert_eq!(jaccard_from_signatures(&sig, &sig), 1.0);
    }

    #[test]
    fn test_jaccard_different_signatures() {
        let sig1 = vec![1, 2, 3, 4, 5];
        let sig2 = vec![6, 7, 8, 9, 10];
        assert_eq!(jaccard_from_signatures(&sig1, &sig2), 0.0);
    }
}
