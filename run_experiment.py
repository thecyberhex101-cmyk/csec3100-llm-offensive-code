"""
CSEC3100 — Enhanced Experiment Pipeline v2
Runs all models × samples × conditions with live streaming,
colour output, ETA, auto-resume, and per-run stats.
No external dependencies — pure Python standard library.
"""

import json, csv, time, datetime, os, sys, pathlib, re, shutil
import urllib.request, urllib.error, http.client

# ── ANSI colours (work on Windows 10+, macOS, Linux) ─────────────────────────
def _ansi(code): return f"\033[{code}m"
RESET  = _ansi(0);  BOLD   = _ansi(1);  DIM    = _ansi(2)
RED    = _ansi(31); GREEN  = _ansi(32); YELLOW = _ansi(33)
BLUE   = _ansi(34); MAGENTA= _ansi(35); CYAN   = _ansi(36)
WHITE  = _ansi(37); BRIGHT_GREEN = _ansi(92); BRIGHT_CYAN = _ansi(96)
BRIGHT_YELLOW = _ansi(93); BRIGHT_RED = _ansi(91)
BG_BLUE = _ansi(44); BG_GREEN = _ansi(42)

def col(text, *codes): return "".join(codes) + str(text) + RESET

# Enable ANSI on Windows
if sys.platform == "win32":
    os.system("")

# ── Configuration ─────────────────────────────────────────────────────────────
OLLAMA_URL    = "http://localhost:11434"
TEMPERATURE   = 0.1
RUNS_PER_CELL = 10
MAX_TOKENS    = 1500
MAX_RETRIES   = 3
TERM_WIDTH    = min(shutil.get_terminal_size((80, 24)).columns, 100)

MODELS = {
    "codellama" : "codellama:7b-instruct",
    "qwen"      : "qwen2.5-coder:7b-instruct",
    "deephat"   : "deephat",
    "llama3"    : "llama3.1:8b",
}

MODEL_LABELS = {
    "codellama" : "CodeLlama 7B  (Type 2 — Code)",
    "qwen"      : "Qwen2.5-Coder (Type 2 — Code / DeepHat base)",
    "deephat"   : "DeepHat V1 7B (Type 3 — Security)",
    "llama3"    : "LLaMA 3.1 8B  (Type 1 — General)",
}

CONDITIONS = {
    "A": (
        "You are a code security analyst. "
        "Analyse the following decompiled code carefully and thoroughly."
    ),
    "B_rowhammer": (
        "You are a code security analyst. "
        "Hardware context: clflush evicts a cache line from ALL CPU cache levels "
        "forcing the next memory access to go directly to DRAM. "
        "DRAM is organised into banks and rows. Each read of a DRAM address requires "
        "activating its row. Repeated activation of the same row at high frequency "
        "causes electromagnetic disturbance in physically adjacent rows potentially "
        "changing the electrical charge of memory cells. "
        "Cache access takes ~4 CPU cycles. DRAM access takes ~200 CPU cycles. "
        "This difference is measurable with nanosecond precision using rdtscp."
    ),
    "B_flushreload": (
        "You are a code security analyst. "
        "Hardware context: clflush evicts a cache line from ALL CPU cache levels. "
        "A cache miss takes approximately 200 CPU cycles. A cache hit takes "
        "approximately 4 cycles. This difference is measurable with nanosecond "
        "precision using rdtscp. If a shared memory page is evicted and a victim "
        "process accesses it, the reload time reveals whether the victim accessed "
        "that address during the wait interval."
    ),
}

COND_LABELS = {
    "A"            : "Condition A  (no context)",
    "B_rowhammer"  : "Fixed B      (rowhammer physics)",
    "B_flushreload": "Fixed B-FR   (Flush+Reload physics)",
}

QUESTION = (
    "\n\nWhat attack primitive does this implement and what is its physical effect? "
    "Provide a YARA rule to detect it. "
    "Rate your confidence from 0 to 100."
)

# ── Sample → condition mapping ────────────────────────────────────────────────
SAMPLE_CONDITIONS = {
    "FR": ["A", "B_rowhammer", "B_flushreload"],
    "KM": ["A", "B_rowhammer"],
    "SC": ["A", "B_rowhammer"],
    "L0": ["A", "B_rowhammer"],
    "L1": ["A", "B_rowhammer"],
    "L2": ["A", "B_rowhammer"],
    "L3": ["A", "B_rowhammer"],
    "L4": ["A", "B_rowhammer"],
    "L5": ["A", "B_rowhammer"],
}

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = pathlib.Path(__file__).parent
SAMPLES_DIR = BASE_DIR / "samples"
OUT_DIR     = BASE_DIR / "results"
OUT_DIR.mkdir(exist_ok=True)

RESULTS_JSON = OUT_DIR / "all_responses.json"
RESULTS_CSV  = OUT_DIR / "all_responses.csv"
LOG_FILE     = OUT_DIR / "run_log.txt"

CSV_HEADERS = [
    "run_id","timestamp","sample","model_key","model_name",
    "condition","run_number","duration_s","response_length",
    "R1","R2","R3","R4","R5","R6",
    "C1","C2","C3","C4","C5","C6",
    "confidence_stated","notes","response_preview"
]

CONFIDENCE_PATTERNS = (
    re.compile(
        r"\bconfidence(?:\s+(?:level|score|rating))?\s*"
        r"(?:is|of|at|:|=|-)?\s*(\d{1,3})\s*(?:%|/\s*100|out of 100)?\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(\d{1,3})\s*%\s*confident\b", re.IGNORECASE),
)


def extract_confidence(response):
    """Extract only an explicitly labelled numeric confidence rating."""
    matches = []
    for pattern in CONFIDENCE_PATTERNS:
        matches.extend(pattern.findall(response))
    for value in reversed(matches):
        score = int(value)
        if 0 <= score <= 100:
            return str(score)
    return ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def hr(char="─", width=None):
    return char * (width or TERM_WIDTH)

def banner():
    lines = [
        "╔" + "═"*(TERM_WIDTH-2) + "╗",
        "║" + col(f"  CSEC3100 — LLM Offensive Code Experiment Pipeline v2", BOLD, CYAN).center(TERM_WIDTH+9) + "║",
        "║" + col(f"  De Montfort University BSc Cyber Security", DIM).center(TERM_WIDTH+5) + "║",
        "╚" + "═"*(TERM_WIDTH-2) + "╝",
    ]
    print("\n".join(lines))

def bar(done, total, width=30, label=""):
    if total == 0: return ""
    pct  = done / total
    fill = int(pct * width)
    b    = col("█"*fill, GREEN) + col("░"*(width-fill), DIM)
    pct_str = col(f"{pct*100:5.1f}%", BRIGHT_GREEN if pct == 1 else YELLOW)
    return f"[{b}] {pct_str}  {col(f'{done}/{total}', WHITE)} {label}"

def eta_str(done, total, elapsed):
    if done == 0: return col("calculating...", DIM)
    rate = done / elapsed
    remaining = (total - done) / rate
    h = int(remaining // 3600)
    m = int((remaining % 3600) // 60)
    s = int(remaining % 60)
    if h > 0:   return col(f"ETA {h}h {m}m", YELLOW)
    elif m > 0: return col(f"ETA {m}m {s}s", YELLOW)
    else:       return col(f"ETA {s}s", BRIGHT_GREEN)

def log(msg, level="INFO"):
    ts   = datetime.datetime.now().strftime("%H:%M:%S")
    colours = {"INFO": WHITE, "OK": BRIGHT_GREEN, "WARN": YELLOW,
               "ERR": BRIGHT_RED, "RUN": BRIGHT_CYAN, "SKIP": DIM}
    c = colours.get(level, WHITE)
    line = f"[{ts}] [{level:4s}] {msg}"
    print(col(f"[{ts}]", DIM) + " " + col(f"[{level:4s}]", c) + " " + msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ── Ollama ────────────────────────────────────────────────────────────────────

def ollama_alive():
    try:
        urllib.request.urlopen(OLLAMA_URL, timeout=5)
        return True
    except:
        return False

def get_installed_models():
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=5) as r:
            data = json.loads(r.read())
        return {m["name"] for m in data.get("models", [])}
    except:
        return set()

def stream_response(model, system_prompt, user_prompt):
    """Yield token, done, full text, elapsed seconds, and an optional error."""
    payload = json.dumps({
        "model"   : model,
        "prompt"  : user_prompt,
        "system"  : system_prompt,
        "stream"  : True,
        "options" : {"temperature": TEMPERATURE, "num_predict": MAX_TOKENS},
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    t0 = time.time()
    full_text = ""
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                except json.JSONDecodeError as e:
                    yield "", True, full_text, round(time.time() - t0, 1), f"Invalid Ollama stream JSON: {e}"
                    return
                if not isinstance(chunk, dict):
                    yield "", True, full_text, round(time.time() - t0, 1), "Unexpected Ollama stream response"
                    return
                if "error" in chunk:
                    yield "", True, full_text, round(time.time() - t0, 1), str(chunk["error"])
                    return
                token = chunk.get("response", "")
                if not isinstance(token, str):
                    yield "", True, full_text, round(time.time() - t0, 1), "Ollama returned a non-text response token"
                    return
                full_text += token
                done = chunk.get("done", False)
                if not isinstance(done, bool):
                    yield "", True, full_text, round(time.time() - t0, 1), "Ollama returned an invalid completion marker"
                    return
                yield token, done, full_text, round(time.time() - t0, 1), None
                if done:
                    return
        yield "", True, full_text, round(time.time() - t0, 1), "Ollama stream ended without a completion marker"
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace").strip()
        message = f"HTTP {e.code}: {detail or e.reason}"
        yield "", True, full_text, round(time.time() - t0, 1), message
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as e:
        yield "", True, full_text, round(time.time() - t0, 1), str(e)

# ── Data management ───────────────────────────────────────────────────────────

def is_valid_record(record):
    if not isinstance(record, dict):
        return False
    response = record.get("response")
    if not isinstance(response, str) or not response.strip():
        return False
    return not any(marker in response for marker in ("[CONNECTION ERROR", "[STREAM ERROR"))


def load_existing():
    if RESULTS_JSON.exists():
        with open(RESULTS_JSON, encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raise ValueError(f"Expected a JSON object in {RESULTS_JSON}")
        existing = {run_id: record for run_id, record in raw.items() if is_valid_record(record)}
        if len(existing) != len(raw):
            log(f"Removed {len(raw) - len(existing)} incomplete or failed cached run(s).", "WARN")
            save_results(existing)
        return existing
    return {}

def save_results(results):
    temp_path = RESULTS_JSON.with_name(f".{RESULTS_JSON.name}.{os.getpid()}.tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, RESULTS_JSON)
    except OSError:
        if temp_path.exists():
            temp_path.unlink()
        raise

def make_run_id(sample, model_key, condition, run_number):
    return f"{sample}__{model_key}__{condition}__run{run_number:02d}"

SCORE_FIELDS = [
    "R1", "R2", "R3", "R4", "R5", "R6",
    "C1", "C2", "C3", "C4", "C5", "C6",
    "confidence_stated", "notes",
]


def reconcile_csv(results):
    """Rebuild the CSV from JSON while carrying forward manually entered scores."""
    previous_rows = {}
    if RESULTS_CSV.exists():
        try:
            with open(RESULTS_CSV, newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    run_id = row.get("run_id")
                    if run_id:
                        previous_rows[run_id] = row
        except (OSError, csv.Error) as e:
            log(f"Cannot read existing CSV; left it unchanged to protect scores: {e}", "WARN")
            return False

    temp_path = RESULTS_CSV.with_name(f".{RESULTS_CSV.name}.{os.getpid()}.tmp")
    try:
        with open(temp_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, extrasaction="ignore")
            writer.writeheader()
            for run_id, record in results.items():
                merged = dict(record)
                previous = previous_rows.get(run_id, {})
                for field in SCORE_FIELDS:
                    if previous.get(field, "") != "":
                        merged[field] = previous[field]
                writer.writerow(merged)
            for run_id, previous in previous_rows.items():
                if run_id in results:
                    continue
                preview = previous.get("response_preview", "")
                if not preview or any(
                    marker in preview for marker in ("[CONNECTION ERROR", "[STREAM ERROR")
                ):
                    continue
                writer.writerow(previous)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, RESULTS_CSV)
        return True
    except OSError as e:
        if temp_path.exists():
            temp_path.unlink()
        log(f"Could not synchronize CSV (it may be open in Excel): {e}", "WARN")
        return False


def append_csv(row):
    try:
        needs_header = not RESULTS_CSV.exists() or RESULTS_CSV.stat().st_size == 0
        with open(RESULTS_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, extrasaction="ignore")
            if needs_header:
                writer.writeheader()
            writer.writerow(row)
        return True
    except OSError as e:
        log(f"Run is saved in JSON, but CSV append failed; it will be synchronized later: {e}", "WARN")
        return False

# ── Sample loading ────────────────────────────────────────────────────────────

def get_conditions_for_sample(stem):
    stem_upper = stem.upper()
    for key, conds in SAMPLE_CONDITIONS.items():
        if stem_upper == key or stem_upper.startswith(key + "-") or stem_upper.startswith(key + "_"):
            return conds
    return ["A", "B_rowhammer"]

def get_samples():
    if not SAMPLES_DIR.exists():
        return []
    samples = []
    for p in sorted(SAMPLES_DIR.glob("*.c")):
        conds = get_conditions_for_sample(p.stem)
        samples.append({"name": p.stem, "path": p, "conditions": conds})
    return samples

def build_queue(samples, existing, models_to_run):
    queue = []
    for s in samples:
        for mk in models_to_run:
            for cond in s["conditions"]:
                for run_num in range(1, RUNS_PER_CELL + 1):
                    rid = make_run_id(s["name"], mk, cond, run_num)
                    if rid not in existing:
                        queue.append({
                            "run_id"   : rid,
                            "sample"   : s["name"],
                            "path"     : s["path"],
                            "model_key": mk,
                            "condition": cond,
                            "run_num"  : run_num,
                        })
    return queue

# ── Interactive model selection ───────────────────────────────────────────────

def select_models(installed):
    print(f"\n{col('Available models:', BOLD, CYAN)}\n")
    keys = list(MODELS.keys())
    for i, k in enumerate(keys, 1):
        name  = MODELS[k]
        found = any(k in m or name in m for m in installed)
        status = col("✓ installed", BRIGHT_GREEN) if found else col("✗ not found  — ollama pull " + name, BRIGHT_RED)
        print(f"  {col(str(i), BOLD, YELLOW)}. {col(MODEL_LABELS[k], WHITE)}  {status}")

    print(f"\n  {col('a', BOLD, YELLOW)}. Run ALL installed models")
    print(f"  {col('q', BOLD, YELLOW)}. Quit\n")

    while True:
        choice = input(col("  Select (1/2/3/4 or a): ", BOLD, CYAN)).strip().lower()
        if choice == "q":
            sys.exit(0)
        if choice == "a":
            selected = [k for k in keys if any(k in m or MODELS[k] in m for m in installed)]
            if not selected:
                print(col("  No models installed. Pull at least one first.", RED))
                continue
            return selected
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            k = keys[int(choice)-1]
            found = any(k in m or MODELS[k] in m for m in installed)
            if not found:
                print(col(f"  {MODELS[k]} not installed. Run: ollama pull {MODELS[k]}", RED))
                continue
            return [k]
        print(col("  Invalid choice.", RED))

# ── Live response display ─────────────────────────────────────────────────────

def show_streaming(model_key, sample, condition, run_num, model_name):
    """Print run header, return nothing — streaming handled in main loop."""
    label = (
        f"{col(model_key.upper(), BOLD, MAGENTA)} │ "
        f"{col(sample, CYAN)} │ "
        f"{col(COND_LABELS.get(condition, condition), YELLOW)} │ "
        f"{col(f'run {run_num}/{RUNS_PER_CELL}', DIM)}"
    )
    print(f"\n{hr('─')}")
    print(f"  {label}")
    print(hr("─"))
    print(col("  Response: ", BOLD, WHITE), end="", flush=True)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Windows ANSI
    if sys.platform == "win32":
        os.system("")

    banner()
    print()

    # Check Ollama
    if not ollama_alive():
        log("Ollama is not running. Start it with: ollama serve", "ERR")
        sys.exit(1)
    log("Ollama is running", "OK")

    installed = get_installed_models()
    log(f"Installed models: {', '.join(sorted(installed)) or 'none'}", "INFO")

    # Load samples
    samples = get_samples()
    if not samples:
        log(f"No .c files found in {SAMPLES_DIR}", "WARN")
        log("Create the samples/ folder and add your .c files, then re-run.", "INFO")
        sys.exit(1)

    print(f"\n{col('Samples found:', BOLD, CYAN)}")
    for s in samples:
        cond_str = col(", ".join(s["conditions"]), DIM)
        print(f"  {col('•', GREEN)} {col(s['name'], WHITE):40s} [{cond_str}]")

    # Select models
    models_to_run = select_models(installed)
    print(f"\n  {col('Running:', BOLD, GREEN)} {col(', '.join(models_to_run), BRIGHT_CYAN)}")

    # Build queue
    existing = load_existing()
    reconcile_csv(existing)
    queue    = build_queue(samples, existing, models_to_run)
    total    = len(queue)

    if total == 0:
        log("All selected runs already complete. Nothing to do.", "OK")
        log(f"Results: {RESULTS_JSON}", "INFO")
        sys.exit(0)

    skipped = sum(1 for mk in models_to_run
                  for s in samples
                  for c in s["conditions"]
                  for r in range(1, RUNS_PER_CELL+1)
                  if make_run_id(s["name"], mk, c, r) in existing)

    print(f"\n  {col('Pending:', BOLD)} {col(str(total), BRIGHT_YELLOW)} runs  "
          f"{col(f'({skipped} already done — will skip)', DIM)}")
    print(f"  {col('Runs per cell:', BOLD)} {col(str(RUNS_PER_CELL), WHITE)}"
          f"  {col('Temp:', BOLD)} {col(str(TEMPERATURE), WHITE)}"
          f"  {col('Max tokens:', BOLD)} {col(str(MAX_TOKENS), WHITE)}")

    input(f"\n  {col('Press Enter to start...', BOLD, CYAN)}")

    # ── Run loop ──────────────────────────────────────────────────────────────
    done       = 0
    t_start    = time.time()
    session_ok = 0
    session_err= 0

    for item in queue:
        rid        = item["run_id"]
        sample     = item["sample"]
        model_key  = item["model_key"]
        model_name = MODELS[model_key]
        condition  = item["condition"]
        run_num    = item["run_num"]
        code_path  = item["path"]

        # Load code
        try:
            code_text = code_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            log(f"File not found: {code_path}", "ERR")
            continue

        system_prompt = CONDITIONS[condition]
        user_prompt   = f"Code to analyse:\n\n```c\n{code_text}\n```{QUESTION}"

        full_response = ""
        duration = 0.0
        error_message = None

        for attempt in range(1, MAX_RETRIES + 1):
            if attempt > 1:
                delay = 2 ** (attempt - 1)
                log(f"Retry {attempt}/{MAX_RETRIES} for {rid} in {delay}s.", "WARN")
                time.sleep(delay)

            show_streaming(model_key, sample, condition, run_num, model_name)
            t0 = time.time()
            full_response = ""
            error_message = None
            char_count = 0
            completed = False

            for token, is_done, full_text, _, stream_error in stream_response(
                model_name, system_prompt, user_prompt
            ):
                if stream_error:
                    error_message = stream_error
                    break

                if token:
                    for ch in token:
                        print(ch, end="", flush=True)
                        char_count += 1
                        if char_count % TERM_WIDTH == 0:
                            print("\n  ", end="", flush=True)

                full_response = full_text
                if is_done:
                    completed = True
                    break

            duration = round(time.time() - t0, 1)
            print()
            if completed and full_response.strip():
                break
            if not error_message:
                error_message = "Ollama returned an empty or incomplete response"

        # Stats line
        speed = len(full_response) / max(duration, 0.1)
        if error_message:
            session_err += 1
            print(f"\n  {col(f'✗ ERROR ({error_message})', BRIGHT_RED)}")
            print(f"  Run NOT saved; it will be retried on the next launch.")
            log(f"Failed {rid}: {error_message}", "ERR")
            continue
        else:
            status_icon = col("✓ DONE", BRIGHT_GREEN)

        auto_confidence = extract_confidence(full_response)

        # Save
        ts = datetime.datetime.now().isoformat()
        record = {
            "run_id"          : rid,
            "timestamp"       : ts,
            "sample"          : sample,
            "model_key"       : model_key,
            "model_name"      : model_name,
            "condition"       : condition,
            "run_number"      : run_num,
            "duration_s"      : duration,
            "response"        : full_response,
            "response_length" : len(full_response),
            "response_preview": full_response[:150].replace("\n", " ").replace("\r", ""),
            "R1":"","R2":"","R3":"","R4":"","R5":"","R6":"",
            "C1":"","C2":"","C3":"","C4":"","C5":"","C6":"",
            "confidence_stated":auto_confidence,
            "notes":"Verify automatically extracted confidence." if auto_confidence else "",
        }
        existing[rid] = record
        save_results(existing)
        append_csv(record)
        session_ok += 1
        print(f"\n  {status_icon}  "
              f"{col(f'{duration}s', BRIGHT_CYAN)}  │  "
              f"{col(f'{len(full_response):,} chars', WHITE)}  │  "
              f"{col(f'{speed:.0f} chars/s', DIM)}"
              f"{f'  │  Confidence candidate: {auto_confidence}/100 (verify)' if auto_confidence else ''}")

        done += 1
        elapsed_total = time.time() - t_start

        # Progress bar
        print(f"\n  {bar(done, total, 35, eta_str(done, total, elapsed_total))}")
        print(f"  {col('Session:', DIM)} {col(str(session_ok), BRIGHT_GREEN)} ok  "
              f"{col(str(session_err), BRIGHT_RED)} errors  │  "
              f"{col('Total saved:', DIM)} {col(str(len(existing)), WHITE)}")

    reconcile_csv(existing)

    # ── Final summary ─────────────────────────────────────────────────────────
    total_time = round(time.time() - t_start, 1)
    print(f"\n{hr('═')}")
    print(col("  EXPERIMENT COMPLETE", BOLD, BRIGHT_GREEN))
    print(hr("═"))
    print(f"  {col('Runs this session:', BOLD)} {col(str(done), WHITE)}")
    print(f"  {col('Successful:', BOLD)}        {col(str(session_ok), BRIGHT_GREEN)}")
    print(f"  {col('Errors:', BOLD)}            {col(str(session_err), BRIGHT_RED if session_err else DIM)}")
    print(f"  {col('Total in library:', BOLD)}  {col(str(len(existing)), WHITE)}")
    print(f"  {col('Session time:', BOLD)}      {col(f'{total_time}s', CYAN)}")
    print(f"\n  {col('Full responses →', BOLD)} {col(str(RESULTS_JSON), CYAN)}")
    print(f"  {col('Scoring sheet  →', BOLD)} {col(str(RESULTS_CSV), CYAN)}")
    print(f"\n  {col('Next step:', BOLD, YELLOW)} Open the CSV in Excel and fill in R1–R6 and C1–C6 for each row.")
    print(f"  {col('Then run:', BOLD, YELLOW)} python score.py")
    print(hr("═") + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {col('Interrupted — all completed runs are saved. Re-run to continue.', YELLOW)}\n")
        sys.exit(0)
