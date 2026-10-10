# SOC AI Assistant

A local, privacy-first triage assistant for Wazuh alerts. It pulls alerts from the
Wazuh Indexer, classifies them with a small local LLM (Ollama, qwen2.5:1.5b), and
makes the final decision with deterministic Python rules. Nothing leaves the machine.

## Design
- **Code for facts and decisions, model for understanding.** Severity comes from
  rule.level; the model only picks a category, and the threat/noise decision is
  derived from that category in code.
- Rule layer handles known cases (low-level events, dpkg, SCA/CIS findings, FIM by
  file path, successful SSH after repeated failures).
- Model output is validated: invalid JSON is rejected, invented evidence is replaced
  with the original log line, and failures are stored as failed (never as safe).
- Logs are passed to the model as untrusted data.
- Results are stored in SQLite so each alert is analysed once.

## Results (lab, single Kali VM)
| Test | Result | Notes |
|---|---|---|
| Model alone, no rules, risky categories only | 46% (69 alerts) | model over-flags threats |
| Model alone, after adding benign categories | 74% (69 alerts), FN=0 | design mattered more than model size |
| Full hybrid system, scenario-labelled | 100% (37 alerts: 8 threat / 29 noise) | 31 decided by rules, 6 by model |
| Lab totals | 809 alerts, 96 flagged as threat | |

## Limitations (please read)
- Small sample; only 8 threat samples in the hybrid evaluation. Treat 100% as a
  pipeline sanity check, not as proof of real-world accuracy.
- Single lab, simple scenarios (failed SSH, new user, package changes, file changes).
- Rules were written after seeing these event types, so the evaluation is partly circular.
- Several decisions are lab-specific simplifications (e.g. port changes treated as
  noise, successful SSH as noise unless preceded by failures).
- A new alert type (SCA/CIS) was initially misclassified, which shows results do not
  automatically generalise.

## Run
```
cd ~/wazuh-docker/single-node && docker compose start   # wait ~4 min
cd ~/soc-ai && source venv/bin/activate
python worker.py --loop
streamlit run app2.py --server.headless true --server.address 0.0.0.0 
python -m pytest tests -q
```
Set WAZUH_PASS as an environment variable; do not commit credentials.
