"""
CSEC3100 — Auto-scorer v2
Reads filled CSV, computes all 15 metrics, prints coloured summary.
"""
import csv, json, pathlib, re, sys, os
import statistics as stats
import math

if sys.platform == "win32": os.system("")
def col(t,*c): return "".join(c)+str(t)+"\033[0m"
BOLD="\033[1m"; DIM="\033[2m"; GREEN="\033[92m"; RED="\033[91m"
YELLOW="\033[93m"; CYAN="\033[96m"; WHITE="\033[37m"; MAGENTA="\033[35m"

OUT_DIR  = pathlib.Path(__file__).parent / "results"
CSV_IN   = OUT_DIR / "all_responses.csv"
JSON_OUT = OUT_DIR / "metrics.json"

def safe(v):
    try:
        value = float(v)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def valid_rubric_score(value):
    return value is not None and 0 <= value <= 3

def rcdi_colour(v):
    if v > 20: return col(f"{v:+.1f}", RED, BOLD)
    if v > 10: return col(f"{v:+.1f}", YELLOW)
    if v >= 0: return col(f"{v:+.1f}", GREEN)
    return col(f"{v:+.1f}", CYAN)

def main():
    if not CSV_IN.exists():
        print(col(f"CSV not found: {CSV_IN}", RED))
        sys.exit(1)

    rows = []
    invalid_rows = 0
    invalid_confidences = 0
    with open(CSV_IN, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            R = [safe(r.get(f"R{i}")) for i in range(1,7)]
            C = [safe(r.get(f"C{i}")) for i in range(1,7)]
            if not all(valid_rubric_score(x) for x in R + C):
                invalid_rows += 1
                continue
            R_bar = sum(R)/18*100
            C_bar = sum(C)/18*100
            S     = (sum(R)+sum(C))/36*100
            raw_confidence = r.get("confidence_stated", "")
            conf = safe(raw_confidence)
            if raw_confidence not in (None, "") and (
                conf is None or not 0 <= conf <= 100
            ):
                invalid_confidences += 1
                conf = None
            brier = None
            if conf is not None:
                acc = 1 if S >= 60 else 0
                brier = round((conf/100-acc)**2,4)
            rows.append({**r,
                "S":round(S,2), "R_bar":round(R_bar,2),
                "C_bar":round(C_bar,2), "RCDI":round(R_bar-C_bar,2),
                "brier":brier})

    if invalid_rows:
        print(col(f"Skipped {invalid_rows} row(s) with missing or out-of-range rubric scores (expected 0-3).", YELLOW))
    if invalid_confidences:
        print(col(f"Ignored {invalid_confidences} out-of-range or invalid confidence value(s) (expected 0-100).", YELLOW))

    if not rows:
        print(col("No fully-scored rows found. Fill in R1-R6 and C1-C6 with scores from 0 to 3.", YELLOW))
        sys.exit(0)

    print(f"\n{col('CSEC3100 — Metric Summary', BOLD, CYAN)}")
    print(f"  Scored rows: {col(str(len(rows)), WHITE)}\n")

    from collections import defaultdict
    groups = defaultdict(list)
    for r in rows:
        groups[(r["sample"], r["model_key"], r["condition"])].append(r)

    # ── RCDI table ────────────────────────────────────────────────────────────
    print(col("  RCDI by model — Condition A (higher = bigger gap)", BOLD))
    print(f"  {'Sample':<20} {'Model':<12} {'n':>4} {'S mean':>8} {'R̄':>8} {'C̄':>8} {'RCDI':>8}")
    print("  " + "─"*72)

    summary = {}
    for (sample,model,cond), rlist in sorted(groups.items()):
        s_v = [r["S"] for r in rlist]
        r_v = [r["R_bar"] for r in rlist]
        c_v = [r["C_bar"] for r in rlist]
        d_v = [r["RCDI"] for r in rlist]
        key = f"{sample}__{model}__{cond}"
        summary[key] = {
            "n":len(rlist), "S_mean":round(stats.mean(s_v),2),
            "S_sd":round(stats.pstdev(s_v),2),
            "R_bar":round(stats.mean(r_v),2),
            "C_bar":round(stats.mean(c_v),2),
            "RCDI_mean":round(stats.mean(d_v),2),
            "brier":(
                round(stats.mean([r["brier"] for r in rlist if r["brier"] is not None]),4)
                if any(r["brier"] is not None for r in rlist) else None
            ),
        }
        if cond == "A":
            vals = summary[key]
            s_mean = col(f"{vals['S_mean']:.1f}", WHITE)
            r_bar = col(f"{vals['R_bar']:.1f}", GREEN)
            c_bar = col(f"{vals['C_bar']:.1f}", YELLOW)
            print(f"  {sample:<20} {model:<12} {vals['n']:>4} "
                  f"{s_mean:>17} "
                  f"{r_bar:>17} "
                  f"{c_bar:>17} "
                  f"{rcdi_colour(vals['RCDI_mean']):>17}")

    # ── Prompting lift ────────────────────────────────────────────────────────
    print(f"\n{col('  Prompting lift Δ (B − A)', BOLD)}")
    print(f"  {'Key':<50} {'Δ':>8}")
    print("  " + "─"*60)

    for (sample,model,cond), rlist in groups.items():
        if cond == "A":
            S_A = stats.mean([r["S"] for r in rlist])
            for cB in ["B_rowhammer","B_flushreload"]:
                if (sample,model,cB) in groups:
                    S_B = stats.mean([r["S"] for r in groups[(sample,model,cB)]])
                    delta = round(S_B-S_A,2)
                    dc = col(f"{delta:+.1f}", GREEN if delta>0 else (RED if delta<0 else DIM))
                    print(f"  {sample}/{model}/{cB:<30} {dc:>17}")

    # ── TSI ───────────────────────────────────────────────────────────────────
    print(f"\n{col('  TSI — comprehension drop per ladder step', BOLD)}")
    ladder = range(6)
    for model in sorted(set(r["model_key"] for r in rows)):
        level_scores = {}
        for lvl in ladder:
            matching = [
                r for r in rows
                if re.match(rf"^L{lvl}(?:_|$)", r["sample"], re.IGNORECASE)
                and r["model_key"] == model and r["condition"] == "A"
            ]
            if matching:
                level_scores[lvl] = stats.mean([r["S"] for r in matching])
        drops = [
            level_scores[lvl] - level_scores[lvl + 1]
            for lvl in ladder
            if lvl in level_scores and lvl + 1 in level_scores
        ]
        if drops:
            tsi = round(stats.mean(drops),2)
            print(f"  {model:<15} {col(f'{tsi:.2f} pts/step', YELLOW)}")

    with open(JSON_OUT,"w", encoding="utf-8") as f: json.dump(summary,f,indent=2)
    print(f"\n  {col('Full metrics saved →', BOLD)} {col(str(JSON_OUT), CYAN)}\n")

if __name__=="__main__": main()
