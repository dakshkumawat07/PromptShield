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
- [ ] v0.1: Core data models and first attack module
- [ ] v0.2: Target connector and demo vulnerable bot
- [ ] v0.3: Scoring engine
- [ ] v0.4: Reports (JSON, then HTML)
- [ ] v1.0: CLI, tests, CI, documentation

## 🔮 Planned Improvements
- More attack families (indirect injection, encoding tricks)
- OWASP LLM Top 10 mapping for every finding

## ▶️ How to Use
Coming soon.

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
