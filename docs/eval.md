# rigseal eval: rules only

Run 2026-11-07 in 9s. No ML, no LLM judge: rules R2-R16 only (R18 left out).
Dataset: [ProtectSkills/MaliciousSkillBench](https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench) at `d4b42ce5766a`, `source_disjoint` split **test**: 839 malicious, 545 benign SKILL.md texts.
Real benign skills: 35 from anthropics-skills `2c5958ecac7c`, obra-superpowers `22f0b463e7a5`.

## Overall

| Flag when | Recall (malicious caught) | False alarms, benchmark benign | False alarms, real skills |
|---|---|---|---|
| any high finding | 2.7% (23/839) | 0.7% (4/545) | 0.0% (0/35) |
| any medium+ finding | 3.7% (31/839) | 6.4% (35/545) | 5.7% (2/35) |

## Per rule

| Rule | Malicious hit | Benchmark benign hit | Real skills hit |
|---|---|---|---|
| R7 | 4 (0.5%) | 0 (0.0%) | 0 |
| R8 | 3 (0.4%) | 0 (0.0%) | 0 |
| R10 | 7 (0.8%) | 0 (0.0%) | 0 |
| R11 | 6 (0.7%) | 0 (0.0%) | 0 |
| R12 | 0 (0.0%) | 0 (0.0%) | 1 |
| R14 | 15 (1.8%) | 35 (6.4%) | 1 |
| R15 | 2 (0.2%) | 0 (0.0%) | 0 |

## Context

Cisco skill-scanner reports on the same frozen test split (839 malicious, 545 benign): rules alone 7.7% recall at HIGH with 4.0% false positives; with a Gemma 4 26B judge, 66.7% at MEDIUM+ (15.4% FPR) and 33.7% at HIGH (6.4% FPR). [Source](https://github.com/cisco-ai-defense/skill-scanner#measured-results). Not rerun here.

Rules alone miss most of this benchmark: many malicious samples describe the attack in prose with no code to match. Off-the-shelf prompt-injection classifiers do not close that gap ([docs/eval-classifier.md](eval-classifier.md)); a local judge is meant to. The lockfile does not depend on detection: any change is drift.

Rules were tuned on the `train` split only; `test` is for reporting. Reproduce: `uv run --group eval python evals/fetch.py && uv run --group eval python evals/run.py --split test`.
