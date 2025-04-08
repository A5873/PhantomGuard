# Example Python-Rust Integration

This example demonstrates how to use the Rust components from Python code for optimized security analysis.

## Basic Integration Example

```python
from rootkithunter.core import RustyAnalyzer

def main():
    analyzer = RustyAnalyzer()

    # Memory analysis (Rust)
    memory_threats = analyzer.scan_memory()

    # Process inspection (Rust)
    suspicious_processes = analyzer.inspect_processes()

    # Network monitoring (Python + Rust)
    network_anomalies = analyzer.monitor_network()

    # Report generation (Python)
    generate_report(memory_threats, suspicious_processes, network_anomalies)
```

## Implementation Details

### Python Side

The `RustyAnalyzer` class provides a Python-friendly interface to the Rust components:

```python
# rootkithunter/core/rusty_analyzer.py
from typing import List, Dict, Any
import rootkithunter_rs  # Rust bindings

class RustyAnalyzer:
    """
    High-performance security analyzer using Rust components.
    """

    def scan_memory(self) -> List[Dict[str, Any]]:
        """
        Scan system memory for threats using Rust implementation.

        Returns:
            List of detected memory threats
        """
        # Call the Rust function through bindings
        return rootkithunter_rs.memory.analyze_memory()

    def inspect_processes(self) -> List[Dict[str, Any]]:
        """
        Inspect running processes using Rust implementation.

        Returns:
            List of suspicious processes
        """
        return rootkithunter_rs.process.analyze_processes()

    def monitor_network(self) -> List[Dict[str, Any]]:
        """
        Monitor network traffic using Rust implementation.

        Returns:
            List of network anomalies
        """
        return rootkithunter_rs.network.analyze_network()
```

### Rust Side

The Rust implementation is exposed to Python using PyO3:

```rust
// src/memory/mod.rs
use pyo3::prelude::*;
use anyhow::Result;

#[pyfunction]
pub fn analyze_memory() -> PyResult<Vec<PyObject>> {
    // Memory analysis implementation
    // ...

    // Convert results to Python objects
    Python::with_gil(|py| {
        // Convert Rust results to Python objects
        // ...
    })
}
```

## Building the Integration

To build the Python-Rust integration:

1. Install the PyO3 dependencies:
   ```bash
   pip install maturin
   ```

2. Add PyO3 to your Rust dependencies:
   ```toml
   [dependencies]
   pyo3 = { version = "0.16", features = ["extension-module"] }
   ```

3. Build the extension module:
   ```bash
   cd rust/rootkithunter
   maturin develop
   ```

## Performance Benefits

The hybrid approach provides several benefits:

1. **Speed**: Memory analysis is up to 50x faster when implemented in Rust
2. **Resource usage**: Lower memory footprint for intensive operations
3. **Concurrency**: Better handling of concurrent operations
4. **Safety**: Memory-safe operations even when dealing with low-level system access

This integration approach gives you the best of both worlds: Python's ease of use and extensive libraries combined with Rust's performance and safety.
