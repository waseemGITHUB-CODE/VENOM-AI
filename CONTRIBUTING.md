# Contributing to VENOM AI

Thanks for your interest in making VENOM better! 🐍

## Ways to Contribute

- 🐛 **Report bugs** — open an issue with steps to reproduce
- 💡 **Suggest features** — open an issue describing the idea
- 🔧 **Submit code** — fork, branch, PR (see below)
- 📖 **Improve docs** — README, setup guides, code comments
- 🧪 **Add attack engines** — the biggest area of impact right now

## High-Impact Areas

We especially welcome help with:

1. **Remaining OWASP engines (A06–A10)** — the scanner currently ships A01–A05.
   - `A06` Insecure Design — business logic flaws, race conditions, workflow bypass
   - `A07` Authentication Failures — brute-force detection, session fixation, weak passwords
   - `A08` Software/Data Integrity — insecure deserialization, unsigned tokens
   - `A09` Logging & Alerting Failures — silent failure detection, user enumeration
   - `A10` Exception Mishandling — malformed input, stack-trace leakage, race conditions
   - Each engine lives in `backend/security/attack_engines/` — copy an existing one (e.g. `a05_injection.py`) as a template.
2. **Tech fingerprints** — add detections in `backend/security/recon_engine.py`
3. **AI prompt tuning** — improve `backend/security/ai_enrichment.py` and `ai_test_planner.py`
4. **Reducing false positives** — improve the verification logic

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/venom-ai.git
cd venom-ai
cp backend/.env.example backend/.env    # add your Groq key
docker compose up --build
```

## Pull Request Process

1. **Fork** the repo and create a branch: `git checkout -b feature/a06-engine`
2. **Make your changes** — keep the style consistent with surrounding code
3. **Test locally** — run a scan against a legal demo target (e.g. `http://zero.webappsecurity.com`) and confirm your engine produces findings
4. **Commit** with a clear message
5. **Open a PR** describing what you changed and why

## Writing a New Attack Engine

Every engine follows the same shape:

```python
# backend/security/attack_engines/aXX_name.py
from .common import AttackClient, Finding

def run_aXX_engine(plan, endpoints, forms, target_url, max_rps=10.0):
    findings = []
    client = AttackClient(max_rps=max_rps)
    try:
        # ... your active tests here ...
        # Each confirmed issue -> findings.append(Finding(...))
    finally:
        client.close()
    return findings
```

Then wire it into `backend/security/attack_orchestrator.py` (copy how A05 is wired) and add its code (`"A06"`, etc.) to `DEFAULT_ENABLED_CATEGORIES` in `backend/routes/attack.py`.

**Important:** payloads must be **safe** — detect via reflection/error/timing, never destroy data (no `DROP TABLE`, no `rm -rf`, no actual account takeover).

## Code of Conduct

Be respectful. This is a security tool — use and discuss it ethically. No help with illegal activity.

## License

By contributing, you agree your contributions are licensed under the [Apache License 2.0](LICENSE).
