# Ransomware Detector Pro

A modular ransomware detection system combining static heuristics, sandbox behavioral analysis, and machine learning.

## Goals
- Multi-layer detection (static + dynamic + telemetry)
- Reproducible research and demo-ready on GitHub
- Explainable alerts and forensic artifacts

## Quick start (Python)
1. Create a venv:

python -m venv venv
source venv/bin/activate # on Windows: venv\Scripts\activate

2. Install:

pip install -r requirements.txt

3. Run a simple static scan:

python src/static_detector/static_detector.py /path/to/sample.exe


## What’s included
- `static_detector` : entropy checks, suspicious imports, simple heuristics
- `models` : training scripts and model artifacts (placeholder)
- `dynamic` : parsers for sandbox output (placeholder)
- `demo` : demo steps & test scenarios

## Next steps
- Add curated datasets, labels, and training notebooks
- Integrate Cuckoo sandbox & capture behavior traces
- Build detection API & dashboards

## Contributing
Open an issue or PR. Keep everything reproducible and documented.
