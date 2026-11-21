# 🛡️ PromptShield

> An open-source toolkit that red-teams LLM applications with prompt injection, jailbreak and data-leak attacks, then scores their resistance and generates reports.

## 📌 Project Overview
PromptShield tests whether an LLM-powered app (chatbot, agent, API) can be tricked into ignoring its instructions or leaking data. It runs a library of attacks, judges each result, and produces a clear security report.

> ⚠️ **Ethical use:** only test applications you own or have written permission to test.

## ✨ Features (planned)
- Attack modules: prompt injection, jailbreaks, system-prompt leaks
- Pluggable targets (local demo bot, HTTP APIs)
- Automatic scoring of each attack
- JSON and HTML reports
- Payloads stored as data files in `rules/`

## 🧠 Concepts Learned
- (updated as the project grows)

## 📈 Project Progress
- [x] v0.0: Project skeleton and README
- [x] v0.1: Core data models and first attack module
- [x] v0.2: Target interface and mock targets
- [x] v0.3: Canary scoring engine and runner
- [x] v0.4: Results summary and CLI (working MVP)
- [ ] v0.5: More attack families (jailbreaks, system-prompt leaks)
- [ ] v0.6: Real targets (HTTP APIs, local LLMs)
- [ ] v0.7: JSON and HTML reports
- [ ] v1.0: CI, documentation, PyPI release

## 🔮 Planned Improvements
- More attack families (indirect injection, encoding tricks)
- OWASP LLM Top 10 mapping for every finding

## ▶️ How to Use
**Install (development):**

```bash
git clone https://github.com/dakshkumawat07/PromptShield.git
cd PromptShield
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

**Run attacks against a built-in mock target:**

```bash
promptshield run --rules rules/prompt_injection.json --target mock-vulnerable
promptshield run --rules rules/prompt_injection.json --target mock-secure
```

**Example output (mock-vulnerable):**

```
Target: mock-vulnerable
  [SUCCESS] PI-001 Basic instruction override
  [SUCCESS] PI-002 Polite override
  [SUCCESS] PI-003 Fake system message
  [SUCCESS] PI-004 Delimiter escape
  [SUCCESS] PI-005 Maintenance mode role change

Attacks judged: 5, succeeded: 5 (100%)
Errors (not judged): 0
By category:
  prompt_injection: 5/5 (100%)
By severity:
  high: 2/2 (100%)
  medium: 3/3 (100%)
```

**Use it in CI:** add `--fail-on-success` and the command exits with code 1 if any attack succeeds.

**Run the tests:** `python -m pytest`

## 🗂️ Project Structure
```
PromptShield/
├── src/promptshield/
│   ├── attacks/
│   ├── targets/
│   ├── scoring/
│   └── reports/
├── rules/
├── tests/
└── docs/
```

## 🛠️ Tech Stack
Python 3.11+

## 🎯 Learning Goal
Understand how LLM applications fail, and build practical tooling to find those failures before attackers do.

## 👤 Author
**Daksh Kumawat**: CSE student at Manipal University Jaipur, focused on cybersecurity.
GitHub: [@dakshkumawat07](https://github.com/dakshkumawat07)

## 🚀 Future Vision
A community-driven library of LLM attack payloads and an easy way to run them in CI.

## 📄 License
Released under the [MIT License](LICENSE).
