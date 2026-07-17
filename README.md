# phishing-detector-python

![CI](https://github.com/SumitSonkusale/phishing-detector-python/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A command-line phishing detection tool that analyses email headers, body text, and embedded URLs for phishing indicators. Built for SOC and blue-team workflows where triage speed matters.

---

## Features

- **Header analysis** — checks `From`/`Reply-To` domain mismatches, missing SPF/DKIM/DMARC authentication headers, and suspicious header patterns
- **Body analysis** — detects urgency language, credential-harvesting phrases, suspicious sender cues, and obfuscated text
- **URL analysis** — flags IP-based URLs, homograph/typosquatting patterns, excessive subdomains, suspicious TLDs, and encoded characters
- **Composite scoring** — per-analyser risk scores aggregated into an overall verdict (`clean` / `suspicious` / `phishing`)
- **JSON output** — structured results suitable for SIEM ingestion or further pipeline processing
- **CLI interface** — accepts raw `.eml` files, piped stdin, or manual input

---

## Project Structure

```
phishing-detector-python/
├── phishing_detector/
│   ├── __init__.py          # Package version + public API
│   ├── models.py            # Dataclasses: AnalysisResult, EmailData
│   ├── header_analyzer.py   # Email header heuristics
│   ├── body_analyzer.py     # Email body heuristics
│   ├── url_analyzer.py      # URL heuristics
│   └── engine.py            # Orchestrator: runs all analysers, returns verdict
├── tests/
│   ├── __init__.py
│   ├── test_url_analyzer.py
│   ├── test_header_analyzer.py
│   └── test_engine.py       # Integration tests (15 test cases)
├── main.py                  # CLI entry point
├── requirements.txt
├── .gitignore
└── LICENSE
```

---

## Installation

```bash
git clone https://github.com/SumitSonkusale/phishing-detector-python.git
cd phishing-detector-python
pip install -r requirements.txt
```

No external runtime dependencies — only the Python standard library. `pytest` and `pytest-cov` are test-only.

---

## Usage

### Analyse an `.eml` file

```bash
python main.py email path/to/email.eml
```

### Analyse a URL directly

```bash
python main.py url "http://secure-login.paypa1.com/verify"
```

### JSON output (for pipeline integration)

```bash
python main.py email path/to/email.eml --json
```

Example output:

```json
{
  "verdict": "phishing",
  "overall_score": 0.87,
  "header_score": 0.75,
  "body_score": 0.80,
  "url_score": 0.95,
  "indicators": [
    "From/Reply-To domain mismatch",
    "Urgency language detected",
    "IP-based URL",
    "Suspicious TLD"
  ]
}
```

---

## How It Works

The tool uses three independent heuristic analysers coordinated by a central engine:

| Analyser | What it checks |
|---|---|
| `HeaderAnalyzer` | Domain alignment, auth headers (SPF/DKIM/DMARC), header anomalies |
| `BodyAnalyzer` | Urgency/fear phrases, credential prompts, sender impersonation cues |
| `UrlAnalyzer` | IP URLs, punycode/homograph domains, typosquatting, encoded chars, suspicious TLDs |

Each analyser returns a normalised score (0.0–1.0) and a list of triggered indicators. The engine aggregates these into a weighted overall score and maps it to a verdict threshold.

---

## Running Tests

```bash
pytest tests/ --tb=short -q --cov=phishing_detector --cov-report=term-missing
```

The test suite covers unit tests for each analyser module and integration tests through the engine (15 test cases total).

---

## CI

GitHub Actions runs the full test suite on every push and pull request to `main`. See [`.github/workflows/test.yml`](.github/workflows/test.yml).

---

## License

[MIT](LICENSE)
