# LinkedIn Post — phishing-detector-python

---

I built a phishing detection tool in Python and put it on GitHub.

It analyses the three main attack surfaces in a suspicious email: headers, body text, and embedded URLs. Each layer runs independently through its own heuristic analyser, and a central engine aggregates the scores into a verdict — clean, suspicious, or phishing.

What the tool checks:
- Header layer: From/Reply-To domain mismatches, missing SPF/DKIM/DMARC records, anomalous header patterns
- Body layer: urgency and fear language, credential-harvesting phrases, sender impersonation cues
- URL layer: IP-based links, punycode/homograph domains, typosquatting patterns, suspicious TLDs, encoded characters

The output is structured JSON, so it pipes cleanly into a SIEM or any downstream triage workflow.

The codebase uses Python dataclasses, type hints throughout, and a full pytest suite (unit tests per analyser + integration tests through the engine). GitHub Actions runs the tests on every push.

No external runtime dependencies — just the standard library.

Code is on GitHub if you want to dig into the implementation or run it against your own samples:
https://github.com/SumitSonkusale/phishing-detector-python

#Python #CyberSecurity #BlueTeam #SOC #EmailSecurity #OpenSource
