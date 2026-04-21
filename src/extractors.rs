// Updated code lines

// Update for line 1751
.map_err(|e| format!("Failed to open RAR: {e}"))?;

// Update for line 1775
.map_err(|e| format!("Failed to open RAR for processing: {e}"))?;

// Update for line 1856
text.push_str(&format!("\n--- {name} (extraction error: {e}) ---\n"));

// Update for line 1890
.map_err(|e| format!("Failed to extract 7z: {e}"))?;

// Update for line 2073
.map_err(|e| format!("Failed to open SQLite database: {e}"))?;

// Update for line 2095
text.push_str(&format!("--- Table: {table} ---\n"));
