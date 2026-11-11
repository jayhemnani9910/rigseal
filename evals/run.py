"""Measure rigseal's rules: recall on malicious skills, false-alarm rate on benign ones.

Each MaliciousSkillBench sample is written as a SKILL.md into a temp folder and scanned like an installed skill.
Samples are only ever read as text.

Usage:
  uv run --group eval python evals/fetch.py
  uv run --group eval python evals/run.py --split train      # while tuning rules
  uv run --group eval python evals/run.py --split test --out docs/eval.md
"""

from __future__ import annotations

import argparse
import csv
import sys
import tempfile
import time
from collections import Counter
from datetime import date
from pathlib import Path

import pyarrow.parquet as pq

from rigseal import capabilities
from rigseal.collectors import common
from rigseal.rules import scan

sys.path.insert(0, str(Path(__file__).parent))
from fetch import BENIGN_REPOS, HF_REPO, HF_REVISION, eval_dir  # noqa: E402

LEVELS = {"high": ("high",), "medium+": ("high", "medium")}


def findings_for(skill_dir: Path) -> list:
    item = common.skill_item("claude-code", skill_dir, "user")
    capabilities.enrich([item])
    return [f for f in scan([item]) if f.rule != "R18"]  # R18 is about declarations, not malice


def load_msb(data: Path, split: str) -> list[tuple[str, int, str]]:
    with (data / "msb" / "splits" / "source_disjoint.csv").open() as f:
        ids = {row["benchmark_id"] for row in csv.DictReader(f) if row["split"] == split}
    table = pq.read_table(data / "msb" / "primary.parquet", columns=["benchmark_id", "label", "skill_text", "public_skill_text"])
    rows = []
    for bid, label, text, public in zip(*(table.column(c).to_pylist() for c in table.column_names), strict=True):
        if bid in ids and (text or public):
            rows.append((bid, int(label), text or public))
    return rows


def benign_skill_dirs(data: Path) -> list[Path]:
    dirs = []
    for name in BENIGN_REPOS:
        root = data / "benign" / name
        dirs += sorted({p.parent for p in root.rglob("SKILL.md") if ".git" not in p.parts})
    return dirs


def pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%" if d else "n/a"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="train", choices=["train", "test", "validation"])
    ap.add_argument("--out", type=Path, help="write the markdown report here")
    args = ap.parse_args()
    data = eval_dir()
    started = time.time()

    samples = load_msb(data, args.split)
    per_rule: dict[str, Counter] = {}
    flagged = {lvl: Counter() for lvl in LEVELS}
    totals = Counter()
    with tempfile.TemporaryDirectory(prefix="rigseal-eval-") as tmp:
        for i, (bid, label, text) in enumerate(samples):
            d = Path(tmp) / f"s{i}"
            d.mkdir()
            (d / "SKILL.md").write_text(text)
            found = findings_for(d)
            kind = "malicious" if label == 1 else "benign"
            totals[kind] += 1
            for rule in {f.rule for f in found}:
                per_rule.setdefault(rule, Counter())[kind] += 1
            for lvl, sevs in LEVELS.items():
                if any(f.severity in sevs for f in found):
                    flagged[lvl][kind] += 1

    real = benign_skill_dirs(data)
    real_flagged = {lvl: 0 for lvl in LEVELS}
    real_hits: Counter = Counter()
    for d in real:
        found = findings_for(d)
        for rule in {f.rule for f in found}:
            real_hits[rule] += 1
        for lvl, sevs in LEVELS.items():
            real_flagged[lvl] += any(f.severity in sevs for f in found)

    lines = [
        "# rigseal eval: rules only",
        "",
        f"Run {date.today().isoformat()} in {time.time() - started:.0f}s. No ML, no LLM judge: rules R2-R16 only (R18 left out).",
        f"Dataset: [{HF_REPO}](https://huggingface.co/datasets/{HF_REPO}) at `{HF_REVISION[:12]}`, "
        f"`source_disjoint` split **{args.split}**: {totals['malicious']} malicious, {totals['benign']} benign SKILL.md texts.",
        f"Real benign skills: {len(real)} from " + ", ".join(f"{n} `{c[:12]}`" for n, (_, c) in BENIGN_REPOS.items()) + ".",
        "",
        "## Overall",
        "",
        "| Flag when | Recall (malicious caught) | False alarms, benchmark benign | False alarms, real skills |",
        "|---|---|---|---|",
    ]
    for lvl in LEVELS:
        lines.append(
            f"| any {lvl} finding | {pct(flagged[lvl]['malicious'], totals['malicious'])} ({flagged[lvl]['malicious']}/{totals['malicious']}) "
            f"| {pct(flagged[lvl]['benign'], totals['benign'])} ({flagged[lvl]['benign']}/{totals['benign']}) "
            f"| {pct(real_flagged[lvl], len(real))} ({real_flagged[lvl]}/{len(real)}) |"
        )
    lines += ["", "## Per rule", "", "| Rule | Malicious hit | Benchmark benign hit | Real skills hit |", "|---|---|---|---|"]
    for rule in sorted(set(per_rule) | set(real_hits), key=lambda r: int(r[1:])):
        c = per_rule.get(rule, Counter())
        lines.append(f"| {rule} | {c['malicious']} ({pct(c['malicious'], totals['malicious'])}) | {c['benign']} ({pct(c['benign'], totals['benign'])}) | {real_hits[rule]} |")
    lines += [
        "",
        "## Context",
        "",
        "Cisco skill-scanner reports on the same frozen test split (839 malicious, 545 benign): rules alone 7.7% recall at HIGH with 4.0% false positives; "
        "with a Gemma 4 26B judge, 66.7% at MEDIUM+ (15.4% FPR) and 33.7% at HIGH (6.4% FPR). "
        "[Source](https://github.com/cisco-ai-defense/skill-scanner#measured-results). Not rerun here.",
        "",
        "Rules alone miss most of this benchmark: many malicious samples describe the attack in prose with no code to match. "
        "Off-the-shelf prompt-injection classifiers do not close that gap ([docs/eval-classifier.md](eval-classifier.md)); a local judge is meant to. The lockfile does not depend on detection: any change is drift.",
        "",
        "Rules were tuned on the `train` split only; `test` is for reporting. Reproduce: `uv run --group eval python evals/fetch.py && uv run --group eval python evals/run.py --split test`.",
    ]
    report = "\n".join(lines) + "\n"
    print(report)
    if args.out:
        args.out.write_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
