"""
CSEC3100 — Interactive Scoring Helper
Shows one full response at a time, prompts for R1-R6 and C1-C6,
saves directly to CSV, auto-resumes from where you left off.
Also validates YARA rules and extracts attack names automatically.
"""

import csv, json, os, sys, re, pathlib, shutil, subprocess, tempfile

# ── ANSI colours ──────────────────────────────────────────────────────────────
if sys.platform == "win32": os.system("")
def col(t,*c): return "".join(c)+str(t)+"\033[0m"
BOLD="\033[1m"; DIM="\033[2m"; GREEN="\033[92m"; RED="\033[91m"
YELLOW="\033[93m"; CYAN="\033[96m"; WHITE="\033[37m"; MAGENTA="\033[35m"
BRIGHT_GREEN="\033[92m"; BG_BLUE="\033[44m"

W = min(shutil.get_terminal_size().columns, 100)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = pathlib.Path(__file__).parent
RESULTS    = BASE_DIR / "results"
CSV_PATH   = RESULTS / "all_responses.csv"
JSON_PATH  = RESULTS / "all_responses.json"

# ── Ground truth anchors ──────────────────────────────────────────────────────
GROUND_TRUTH = {
    "rowhammer": {
        "name"     : "Rowhammer",
        "class"    : "Fault injection — NOT side-channel",
        "mechanism": "clflush → DRAM row activation → electrical disturbance → bit flip",
        "outcome"  : "Bit flips → memory corruption → privilege escalation",
        "privilege": "Ring 3 unprivileged",
    },
    "flushreload": {
        "name"     : "Flush+Reload",
        "class"    : "Side-channel — information leakage — NOT fault injection",
        "mechanism": "flush → wait → reload time measurement → cache hit/miss → victim access revealed",
        "outcome"  : "Memory access pattern leaked → cryptographic key extraction",
        "privilege": "Ring 3 — requires shared memory page with victim",
    },
}

CRITERIA = [
    ("R1", "Key instruction identified (clflush/clflushopt role)"),
    ("R2", "Technique NAMED correctly"),
    ("R3", "Attack TYPE classified correctly (fault inject vs side-channel)"),
    ("R4", "Security OUTCOME mentioned"),
    ("R5", "YARA rule produced"),
    ("R6", "Confidence STATED"),
    ("C1", "WHY instruction matters physically"),
    ("C2", "HOW technique produces physical effect (full chain)"),
    ("C3", "Threat MODEL explained"),
    ("C4", "Physical MECHANISM at hardware level"),
    ("C5", "YARA targets SEMANTIC signatures not just keywords"),
    ("C6", "Confidence CALIBRATED against actual consequence quality"),
]

SCORE_GUIDE = {
    0: col("0 = Absent", RED),
    1: col("1 = Partial", YELLOW),
    2: col("2 = Largely correct", CYAN),
    3: col("3 = Fully correct", BRIGHT_GREEN),
}

# ── Attack name detector ──────────────────────────────────────────────────────
ATTACK_PATTERNS = {
    "rowhammer"     : r'\b(rowhammer|row.hammer|rowhamm)\b',
    "flush+reload"  : r'\b(flush\+reload|flush.reload|flush and reload)\b',
    "spectre"       : r'\bspectre\b',
    "meltdown"      : r'\bmeltdown\b',
    "cache timing"  : r'\bcache.timing\b',
    "side-channel"  : r'\bside.channel\b',
    "tmto"          : r'\btmto\b',
    "cflush ddos"   : r'\bcflush.ddos\b',
    "speculative"   : r'\bspeculative.execution\b',
}

def detect_attack_names(text):
    found = []
    lower = text.lower()
    for name, pattern in ATTACK_PATTERNS.items():
        if re.search(pattern, lower):
            found.append(name)
    return found if found else ["none detected"]

# ── YARA validator ────────────────────────────────────────────────────────────
def validate_yara(response_text):
    """Extract YARA rule from response and validate syntax."""
    # Find YARA rule in response
    yara_match = re.search(
        r'(rule\s+\w+\s*\{.*?\})',
        response_text, re.DOTALL | re.IGNORECASE
    )
    if not yara_match:
        return None, "No YARA rule found"

    rule_text = yara_match.group(1)

    # Basic structural validation without needing yara installed
    has_rule    = bool(re.search(r'\brule\s+\w+', rule_text))
    has_open    = '{' in rule_text
    has_close   = '}' in rule_text
    has_condition = bool(re.search(r'\bcondition\s*:', rule_text))
    has_strings   = bool(re.search(r'\bstrings\s*:', rule_text))

    if not all([has_rule, has_open, has_close, has_condition]):
        return rule_text, "INVALID — missing required sections"

    # Check for semantic vs keyword-only
    hex_patterns = bool(re.search(r'\{[0-9a-fA-F? ]+\}', rule_text))
    keyword_only = bool(re.search(r'\$\w+\s*=\s*"[^"]{3,}"', rule_text))
    all_same = len(set(re.findall(r'\{[0-9a-fA-F? ]+\}', rule_text))) == 1 and \
               len(re.findall(r'\{[0-9a-fA-F? ]+\}', rule_text)) > 2

    if all_same:
        semantic_note = col("WARNING: all hex patterns identical — likely fabricated", RED)
    elif hex_patterns:
        semantic_note = col("Contains hex patterns (potentially semantic)", CYAN)
    elif keyword_only:
        semantic_note = col("Keyword-only strings detected", YELLOW)
    else:
        semantic_note = col("Structure unclear", DIM)

    return rule_text, f"VALID structure | {semantic_note}"

# ── Load data ─────────────────────────────────────────────────────────────────
def load_data():
    if not CSV_PATH.exists():
        print(col(f"CSV not found: {CSV_PATH}", RED))
        sys.exit(1)
    if not JSON_PATH.exists():
        print(col(f"JSON not found: {JSON_PATH}", RED))
        sys.exit(1)

    with open(JSON_PATH, encoding="utf-8") as f:
        responses = json.load(f)

    rows = []
    with open(CSV_PATH, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            rows.append(row)

    return rows, responses

# ── Save scores back to CSV ───────────────────────────────────────────────────
def save_scores(rows):
    if not rows: return
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys(), extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

# ── Scoring session ───────────────────────────────────────────────────────────
def get_ground_truth_for(sample):
    sample_lower = sample.lower()
    if "flush" in sample_lower or "fr-" in sample_lower or "fr_" in sample_lower:
        return GROUND_TRUTH["flushreload"], "Flush+Reload"
    return GROUND_TRUTH["rowhammer"], "Rowhammer"

def get_score(prompt_text, current=""):
    """Get a valid 0-3 score from user."""
    while True:
        val = input(prompt_text).strip()
        if val == "" and current != "":
            return current  # keep existing score
        if val in ("0","1","2","3"):
            return val
        if val.lower() == "s":
            return "skip"
        if val.lower() == "q":
            return "quit"
        print(col("  Enter 0, 1, 2, or 3  (s=skip row, q=quit)", YELLOW))

def score_row(row, full_response, row_index, total_unscored):
    """Display one response and collect scores."""
    os.system("cls" if sys.platform == "win32" else "clear")

    sample    = row["sample"]
    model     = row["model_key"]
    condition = row["condition"]
    run_num   = row["run_number"]
    duration  = row["duration_s"]

    gt, gt_name = get_ground_truth_for(sample)

    # Header
    print(col("═"*W, CYAN))
    print(col(f"  CSEC3100 Scoring Helper  —  {row_index} remaining to score", BOLD, CYAN))
    print(col("═"*W, CYAN))
    print(f"  {col('Sample:', BOLD)}    {col(sample, YELLOW)}")
    print(f"  {col('Model:', BOLD)}     {col(model.upper(), MAGENTA)}  ({row['model_name']})")
    print(f"  {col('Condition:', BOLD)} {col(condition, WHITE)}")
    print(f"  {col('Run:', BOLD)}       {col(run_num, WHITE)} of 10  |  {col(duration+'s', DIM)}")
    print(col("─"*W, DIM))

    # Ground truth reminder
    print(f"\n  {col('GROUND TRUTH — '+gt_name, BOLD, GREEN)}")
    print(f"  {col('Correct name:', DIM)}     {gt['name']}")
    print(f"  {col('Attack class:', DIM)}     {gt['class']}")
    print(f"  {col('Mechanism:', DIM)}        {gt['mechanism']}")
    print(f"  {col('Outcome:', DIM)}          {gt['outcome']}")
    print(col("─"*W, DIM))

    # Auto-analysis
    detected = detect_attack_names(full_response)
    detect_col = BRIGHT_GREEN if gt_name.lower().replace("+","").replace(" ","") in \
                 [d.replace("+","").replace(" ","").replace("-","") for d in detected] else RED
    print(f"\n  {col('Auto-detected attack names:', BOLD)} {col(', '.join(detected), detect_col)}")

    # YARA check
    yara_rule, yara_status = validate_yara(full_response)
    print(f"  {col('YARA validation:', BOLD)} {yara_status}")
    print(col("─"*W, DIM))

    # Full response
    print(f"\n  {col('FULL RESPONSE:', BOLD, WHITE)}\n")
    # Word wrap the response
    words = full_response.split()
    line = "  "
    for word in words:
        if len(line) + len(word) + 1 > W - 2:
            print(line)
            line = "  " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    print(col("\n" + "─"*W, DIM))
    print(f"\n  {col('SCORE GUIDE:', BOLD)}  {' | '.join(SCORE_GUIDE[i] for i in range(4))}")
    print(f"  {col('Commands:', DIM)} Enter score (0-3) | Press Enter to keep existing | s = skip | q = save and quit\n")

    # Score each criterion
    scores = {}
    for key, description in CRITERIA:
        current = row.get(key, "")
        current_display = f" [{col(current, CYAN)}]" if current else ""
        prompt = f"  {col(key, BOLD, YELLOW)} {description}{current_display}: "
        result = get_score(prompt, current)
        if result == "quit":
            return "quit", scores
        if result == "skip":
            return "skip", scores
        scores[key] = result

    # Notes
    current_notes = row.get("notes", "").replace("Verify automatically extracted confidence.", "").strip()
    notes_display = f" [{current_notes}]" if current_notes else ""
    notes = input(f"\n  {col('Notes (optional):', DIM)}{notes_display}: ").strip()
    if notes:
        scores["notes"] = notes

    return "scored", scores

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    os.system("cls" if sys.platform == "win32" else "clear")
    print(f"\n{col('CSEC3100 — Interactive Scoring Helper', BOLD, CYAN)}\n")

    rows, responses = load_data()

    # Find unscored rows
    def is_scored(row):
        return all(row.get(f"R{i}","").strip() in ("0","1","2","3")
                   for i in range(1,7))

    unscored = [r for r in rows if not is_scored(r)]
    scored   = len(rows) - len(unscored)

    print(f"  Total rows:    {col(str(len(rows)), WHITE)}")
    print(f"  Already scored:{col(str(scored), BRIGHT_GREEN)}")
    print(f"  To score:      {col(str(len(unscored)), YELLOW)}")

    if not unscored:
        print(col("\n  All rows scored! Run score.py to compute metrics.", BRIGHT_GREEN))
        return

    # Filter options
    print(f"\n  {col('Filter options:', BOLD)}")
    print(f"  {col('1', YELLOW)} Score all unscored rows in order")
    print(f"  {col('2', YELLOW)} Score one sample only")
    print(f"  {col('3', YELLOW)} Score one model only")
    print(f"  {col('4', YELLOW)} Score Condition A only")
    print(f"  {col('5', YELLOW)} Score Flush+Reload samples only")

    choice = input(f"\n  {col('Choice (1-5):', CYAN)} ").strip()

    if choice == "2":
        samples = sorted(set(r["sample"] for r in unscored))
        for i, s in enumerate(samples, 1):
            print(f"  {col(str(i), YELLOW)}. {s}")
        idx = input("  Pick number: ").strip()
        if idx.isdigit() and 1 <= int(idx) <= len(samples):
            chosen = samples[int(idx)-1]
            unscored = [r for r in unscored if r["sample"] == chosen]
    elif choice == "3":
        models = sorted(set(r["model_key"] for r in unscored))
        for i, m in enumerate(models, 1):
            print(f"  {col(str(i), YELLOW)}. {m}")
        idx = input("  Pick number: ").strip()
        if idx.isdigit() and 1 <= int(idx) <= len(models):
            chosen = models[int(idx)-1]
            unscored = [r for r in unscored if r["model_key"] == chosen]
    elif choice == "4":
        unscored = [r for r in unscored if r["condition"] == "A"]
    elif choice == "5":
        unscored = [r for r in unscored if "fr" in r["sample"].lower()
                    or "flush" in r["sample"].lower()]

    print(f"\n  Scoring {col(str(len(unscored)), YELLOW)} rows. Press Enter to begin.")
    input()

    # Build a fast lookup from run_id to row index
    row_index_map = {r["run_id"]: i for i, r in enumerate(rows)}

    scored_this_session = 0

    for remaining, row in enumerate(unscored, 1):
        run_id = row["run_id"]
        full_response = responses.get(run_id, {}).get("response", "")

        if not full_response:
            print(col(f"  No response found for {run_id} — skipping", YELLOW))
            continue

        result, scores = score_row(
            row, full_response,
            len(unscored) - remaining + 1,
            len(unscored)
        )

        if result == "quit":
            print(col("\n  Saving and quitting...", YELLOW))
            save_scores(rows)
            break

        if result == "skip":
            continue

        # Apply scores to the master rows list
        idx = row_index_map.get(run_id)
        if idx is not None:
            for key, val in scores.items():
                rows[idx][key] = val

        scored_this_session += 1

        # Save after every 5 responses
        if scored_this_session % 5 == 0:
            save_scores(rows)
            print(col(f"\n  Auto-saved at {scored_this_session} responses this session.", DIM))
            input(col("  Press Enter to continue...", DIM))

    save_scores(rows)
    print(f"\n{col('Session complete.', BRIGHT_GREEN)}")
    print(f"  Scored this session: {col(str(scored_this_session), WHITE)}")
    print(f"  Run {col('python score.py', CYAN)} to compute all 15 metrics.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(col("\n\n  Interrupted — progress saved.", YELLOW))
