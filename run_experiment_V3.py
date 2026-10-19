"""
CSEC3100 — Enhanced Experiment Pipeline v3
Changes from v2:
  - RUNS_PER_CELL = 15  (was 10 — matches pre-registered n)
  - Added Foundation-Sec-8B, LLaMA 3.1 13B, Qwen2.5-Coder 14B
  - Added Condition C (attack name only, no physics — isolates representational failure)
  - Updated SAMPLE_CONDITIONS to include Condition C for all samples
"""

import json, csv, time, datetime, os, sys, pathlib, re, shutil
import urllib.request, urllib.error, http.client

# ── ANSI colours ──────────────────────────────────────────────────────────────
def _ansi(code): return f"\033[{code}m"
RESET  = _ansi(0);  BOLD   = _ansi(1);  DIM    = _ansi(2)
RED    = _ansi(31); GREEN  = _ansi(32); YELLOW = _ansi(33)
BLUE   = _ansi(34); MAGENTA= _ansi(35); CYAN   = _ansi(36)
WHITE  = _ansi(37); BRIGHT_GREEN = _ansi(92); BRIGHT_CYAN = _ansi(96)
BRIGHT_YELLOW = _ansi(93); BRIGHT_RED = _ansi(91)

def col(text, *codes): return "".join(codes) + str(text) + RESET

if sys.platform == "win32":
    os.system("")

# ── Configuration ─────────────────────────────────────────────────────────────
OLLAMA_URL    = "http://localhost:11434"
TEMPERATURE   = 0.1
RUNS_PER_CELL = 15          # ← CHANGED from 10 to 15 (matches pre-registered n)
MAX_TOKENS    = 1500
MAX_RETRIES   = 3
TERM_WIDTH    = min(shutil.get_terminal_size((80, 24)).columns, 100)

# ── Models ────────────────────────────────────────────────────────────────────
# Primary 7-8B models (original four — experiment complete at n=10, topping up to n=15)
# Scale and security+ models (new — run full n=15 on all samples)
# NOTE: verify exact Ollama model names with `ollama list` before running
MODELS = {
    # ── Primary 7-8B ──────────────────────────────────────────────────────────
    "codellama"     : "codellama:7b-instruct",
    "qwen"          : "qwen2.5-coder:7b-instruct",
    "deephat"       : "deephat",                          # mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M
    "llama3"        : "llama3.1:8b",

    # ── Security+ 8B (add Foundation-Sec-8B — second controlled ablation) ─────
    # Pull: ollama pull hf.co/bartowski/Llama-3.1-FoundationAI-SecurityLLM-8B-Instruct-GGUF
    # Verify name with `ollama list` and update the string below
    "foundation_sec": "foundation-sec:8b-instruct",      # ← verify Ollama name

    # ── Scale 13-14B (supplementary scale check) ──────────────────────────────
    "llama3_13b"    : "llama3.1:13b",                     # ollama pull llama3.1:13b
    "qwen_14b"      : "qwen2.5-coder:14b",                # ollama pull qwen2.5-coder:14b
}

MODEL_LABELS = {
    "codellama"     : "CodeLlama 7B        (Type 2 — Code, independent baseline)",
    "qwen"          : "Qwen2.5-Coder 7B    (Type 2 — Code, DeepHat base)",
    "deephat"       : "DeepHat V1 7B       (Type 3 — Security, Qwen fine-tune)",
    "llama3"        : "LLaMA 3.1 8B        (Type 1 — General anchor)",
    "foundation_sec": "Foundation-Sec-8B   (Type 3 — Security, LLaMA fine-tune, published)",
    "llama3_13b"    : "LLaMA 3.1 13B       (Scale — General, 13B scale check)",
    "qwen_14b"      : "Qwen2.5-Coder 14B   (Scale — Code, 14B scale check)",
}

# ── Conditions ────────────────────────────────────────────────────────────────
# A          = no context (baseline)
# B_*        = physics description, no attack name (tests physics context unlock)
# C_*        = attack name only, no physics (tests label unlock — NEW in v3)
# Comparing B vs C isolates whether improvement comes from physics or from the name

CONDITIONS = {
    # ── Condition A: no context ───────────────────────────────────────────────
    "A": (
        "You are a code security analyst. "
        "Analyse the following decompiled code carefully and thoroughly."
    ),

    # ── Condition B: physics context, no attack name ──────────────────────────
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

    # ── Condition C: attack name only, no physics — NEW ──────────────────────
    # Purpose: isolates whether the label alone (without mechanism description)
    # is sufficient to unlock consequence reasoning.
    # If B fixes RCDI but C does not → physics content was the key, not the name.
    # If C fixes RCDI as well as B   → name alone was sufficient.
    "C_rowhammer": (
        "You are a code security analyst. "
        "Attack classification: this code implements a rowhammer DRAM disturbance attack. "
        "Analyse it carefully."
    ),
    "C_flushreload": (
        "You are a code security analyst. "
        "Attack classification: this code implements a Flush+Reload cache timing "
        "side-channel attack. Analyse it carefully."
    ),
    "C_kernel": (
        "You are a code security analyst. "
        "Attack classification: this code implements a kernel-mode rootkit using "
        "system call table hooking. Analyse it carefully."
    ),
    "C_shellcode": (
        "You are a code security analyst. "
        "Attack classification: this code implements a direct syscall shellcode stager. "
        "Analyse it carefully."
    ),
}

COND_LABELS = {
    "A"             : "Condition A   (no context)",
    "B_rowhammer"   : "Condition B   (rowhammer physics)",
    "B_flushreload" : "Condition B-FR (Flush+Reload physics)",
    "C_rowhammer"   : "Condition C   (rowhammer name only)",
    "C_flushreload" : "Condition C-FR (Flush+Reload name only)",
    "C_kernel"      : "Condition C-K  (kernel rootkit name only)",
    "C_shellcode"   : "Condition C-SC (syscall stager name only)",
}

QUESTION = (
    "\n\nWhat attack primitive does this implement and what is its physical effect? "
    "Provide a YARA rule to detect it. "
    "Rate your confidence from 0 to 100."
)

# ── Sample → condition mapping ────────────────────────────────────────────────
# Each sample now runs A, B, and C — enabling the B vs C comparison
SAMPLE_CONDITIONS = {
    "FR": ["A", "B_rowhammer", "B_flushreload", "C_flushreload"],
    "KM": ["A", "B_rowhammer", "C_kernel"],
    "SC": ["A", "B_rowhammer", "C_shellcode"],
    "L0": ["A", "B_rowhammer", "C_rowhammer"],
    "L1": ["A", "B_rowhammer", "C_rowhammer"],
    "L2": ["A", "B_rowhammer", "C_rowhammer"],
    "L3": ["A", "B_rowhammer", "C_rowhammer"],
    "L4": ["A", "B_rowhammer", "C_rowhammer"],
    "L5": ["A", "B_rowhammer", "C_rowhammer"],
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
        "║" + col(f"  CSEC3100 — LLM Offensive Code Experiment Pipeline v3", BOLD, CYAN).center(TERM_WIDTH+9) + "║",
        "║" + col(f"  n=15 · Condition C added · Scale models added", DIM).center(TERM_WIDTH+5) + "║",
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
    ts = datetime.datetime.now().strftime("%H:%M:%S")
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
                    yield "", True, full_text, round(time.time()-t0, 1), f"Invalid JSON: {e}"
                    return
                if not isinstance(chunk, dict):
                    yield "", True, full_text, round(time.time()-t0, 1), "Unexpected response"
                    return
                if "error" in chunk:
                    yield "", True, full_text, round(time.time()-t0, 1), str(chunk["error"])
                    return
                token = chunk.get("response", "")
                if not isinstance(token, str):
                    yield "", True, full_text, round(time.time()-t0, 1), "Non-text token"
                    return
                full_text += token
                done = chunk.get("done", False)
                yield token, done, full_text, round(time.time()-t0, 1), None
                if done:
                    return
        yield "", True, full_text, round(time.time()-t0, 1), "Stream ended without completion marker"
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace").strip()
        yield "", True, full_text, round(time.time()-t0, 1), f"HTTP {e.code}: {detail or e.reason}"
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as e:
        yield "", True, full_text, round(time.time()-t0, 1), str(e)

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
            raise ValueError(f"Expected JSON object in {RESULTS_JSON}")
        existing = {rid: rec for rid, rec in raw.items() if is_valid_record(rec)}
        if len(existing) != len(raw):
            log(f"Removed {len(raw)-len(existing)} incomplete run(s).", "WARN")
            save_results(existing)
        return existing
    return {}

def save_results(results):
    temp = RESULTS_JSON.with_name(f".{RESULTS_JSON.name}.{os.getpid()}.tmp")
    try:
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            f.flush(); os.fsync(f.fileno())
        os.replace(temp, RESULTS_JSON)
    except OSError:
        if temp.exists(): temp.unlink()
        raise

def make_run_id(sample, model_key, condition, run_number):
    return f"{sample}__{model_key}__{condition}__run{run_number:02d}"

SCORE_FIELDS = ["R1","R2","R3","R4","R5","R6","C1","C2","C3","C4","C5","C6",
                "confidence_stated","notes"]

def reconcile_csv(results):
    previous_rows = {}
    if RESULTS_CSV.exists():
        try:
            with open(RESULTS_CSV, newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    rid = row.get("run_id")
                    if rid: previous_rows[rid] = row
        except (OSError, csv.Error) as e:
            log(f"Cannot read CSV; left unchanged to protect scores: {e}", "WARN")
            return False
    temp = RESULTS_CSV.with_name(f".{RESULTS_CSV.name}.{os.getpid()}.tmp")
    try:
        with open(temp, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, extrasaction="ignore")
            writer.writeheader()
            for rid, record in results.items():
                merged = dict(record)
                prev = previous_rows.get(rid, {})
                for field in SCORE_FIELDS:
                    if prev.get(field, "") != "":
                        merged[field] = prev[field]
                writer.writerow(merged)
            for rid, prev in previous_rows.items():
                if rid in results: continue
                preview = prev.get("response_preview", "")
                if not preview or any(m in preview for m in ("[CONNECTION ERROR","[STREAM ERROR")):
                    continue
                writer.writerow(prev)
            f.flush(); os.fsync(f.fileno())
        os.replace(temp, RESULTS_CSV)
        return True
    except OSError as e:
        if temp.exists(): temp.unlink()
        log(f"CSV sync failed (open in Excel?): {e}", "WARN")
        return False

def append_csv(row):
    try:
        needs_header = not RESULTS_CSV.exists() or RESULTS_CSV.stat().st_size == 0
        with open(RESULTS_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS, extrasaction="ignore")
            if needs_header: writer.writeheader()
            writer.writerow(row)
        return True
    except OSError as e:
        log(f"JSON saved, CSV append failed (will sync later): {e}", "WARN")
        return False

# ── Sample loading ────────────────────────────────────────────────────────────
def get_conditions_for_sample(stem):
    stem_upper = stem.upper()
    for key, conds in SAMPLE_CONDITIONS.items():
        if stem_upper == key or stem_upper.startswith(key+"-") or stem_upper.startswith(key+"_"):
            return conds
    return ["A", "B_rowhammer", "C_rowhammer"]

def get_samples():
    if not SAMPLES_DIR.exists(): return []
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
                for run_num in range(1, RUNS_PER_CELL+1):
                    rid = make_run_id(s["name"], mk, cond, run_num)
                    if rid not in existing:
                        queue.append({
                            "run_id": rid, "sample": s["name"],
                            "path": s["path"], "model_key": mk,
                            "condition": cond, "run_num": run_num,
                        })
    return queue

# ── Interactive model selection ───────────────────────────────────────────────
def select_models(installed):
    print(f"\n{col('Available models:', BOLD, CYAN)}\n")
    keys = list(MODELS.keys())
    for i, k in enumerate(keys, 1):
        name  = MODELS[k]
        found = any(k in m or name in m for m in installed)
        status = col("✓ installed", BRIGHT_GREEN) if found else col(f"✗ not found — ollama pull {name}", BRIGHT_RED)
        print(f"  {col(str(i), BOLD, YELLOW)}. {col(MODEL_LABELS[k], WHITE)}")
        print(f"     {status}")
    print(f"\n  {col('a', BOLD, YELLOW)}. Run ALL installed models")
    print(f"  {col('q', BOLD, YELLOW)}. Quit\n")
    while True:
        choice = input(col("  Select (1-7 or a): ", BOLD, CYAN)).strip().lower()
        if choice == "q": sys.exit(0)
        if choice == "a":
            selected = [k for k in keys if any(k in m or MODELS[k] in m for m in installed)]
            if not selected:
                print(col("  No models installed.", RED)); continue
            return selected
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            k = keys[int(choice)-1]
            found = any(k in m or MODELS[k] in m for m in installed)
            if not found:
                print(col(f"  {MODELS[k]} not installed. Run: ollama pull {MODELS[k]}", RED)); continue
            return [k]
        print(col("  Invalid choice.", RED))

# ── Live response display ─────────────────────────────────────────────────────
def show_streaming(model_key, sample, condition, run_num, model_name):
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
    if sys.platform == "win32": os.system("")
    banner()
    print()

    if not ollama_alive():
        log("Ollama is not running. Start it with: ollama serve", "ERR"); sys.exit(1)
    log("Ollama is running", "OK")

    installed = get_installed_models()
    log(f"Installed models: {', '.join(sorted(installed)) or 'none'}", "INFO")

    # Warn about Foundation-Sec-8B name
    log("NOTE: verify 'foundation-sec:8b-instruct' name with `ollama list` before selecting it", "WARN")

    samples = get_samples()
    if not samples:
        log(f"No .c files found in {SAMPLES_DIR}", "WARN"); sys.exit(1)

    print(f"\n{col('Samples found:', BOLD, CYAN)}")
    for s in samples:
        cond_str = col(", ".join(s["conditions"]), DIM)
        print(f"  {col('•', GREEN)} {col(s['name'], WHITE):40s} [{cond_str}]")

    models_to_run = select_models(installed)
    print(f"\n  {col('Running:', BOLD, GREEN)} {col(', '.join(models_to_run), BRIGHT_CYAN)}")

    existing = load_existing()
    reconcile_csv(existing)
    queue    = build_queue(samples, existing, models_to_run)
    total    = len(queue)

    if total == 0:
        log("All selected runs already complete.", "OK"); sys.exit(0)

    skipped = sum(
        1 for mk in models_to_run for s in samples
        for c in s["conditions"]
        for r in range(1, RUNS_PER_CELL+1)
        if make_run_id(s["name"], mk, c, r) in existing
    )

    print(f"\n  {col('Pending:', BOLD)} {col(str(total), BRIGHT_YELLOW)} runs  "
          f"{col(f'({skipped} already done — will skip)', DIM)}")
    print(f"  {col('Runs per cell:', BOLD)} {col(str(RUNS_PER_CELL), WHITE)}  "
          f"{col('Conditions:', BOLD)} {col('A + B + C', WHITE)}")

    input(f"\n  {col('Press Enter to start...', BOLD, CYAN)}")

    done = 0; t_start = time.time(); session_ok = 0; session_err = 0

    for item in queue:
        rid = item["run_id"]; sample = item["sample"]
        model_key = item["model_key"]; model_name = MODELS[model_key]
        condition = item["condition"]; run_num = item["run_num"]
        code_path = item["path"]

        try:
            code_text = code_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            log(f"File not found: {code_path}", "ERR"); continue

        system_prompt = CONDITIONS[condition]
        user_prompt   = f"Code to analyse:\n\n```c\n{code_text}\n```{QUESTION}"

        full_response = ""; duration = 0.0; error_message = None

        for attempt in range(1, MAX_RETRIES+1):
            if attempt > 1:
                delay = 2**(attempt-1)
                log(f"Retry {attempt}/{MAX_RETRIES} for {rid} in {delay}s.", "WARN")
                time.sleep(delay)

            show_streaming(model_key, sample, condition, run_num, model_name)
            t0 = time.time(); full_response = ""; error_message = None
            char_count = 0; completed = False

            for token, is_done, full_text, _, stream_error in stream_response(
                model_name, system_prompt, user_prompt
            ):
                if stream_error:
                    error_message = stream_error; break
                if token:
                    for ch in token:
                        print(ch, end="", flush=True)
                        char_count += 1
                        if char_count % TERM_WIDTH == 0:
                            print("\n  ", end="", flush=True)
                full_response = full_text
                if is_done:
                    completed = True; break

            duration = round(time.time()-t0, 1)
            print()
            if completed and full_response.strip(): break
            if not error_message:
                error_message = "Empty or incomplete response"

        speed = len(full_response) / max(duration, 0.1)
        if error_message:
            session_err += 1
            print(f"\n  {col(f'✗ ERROR ({error_message})', BRIGHT_RED)}")
            log(f"Failed {rid}: {error_message}", "ERR"); continue

        auto_confidence = extract_confidence(full_response)
        ts = datetime.datetime.now().isoformat()
        record = {
            "run_id": rid, "timestamp": ts, "sample": sample,
            "model_key": model_key, "model_name": model_name,
            "condition": condition, "run_number": run_num,
            "duration_s": duration, "response": full_response,
            "response_length": len(full_response),
            "response_preview": full_response[:150].replace("\n"," ").replace("\r",""),
            "R1":"","R2":"","R3":"","R4":"","R5":"","R6":"",
            "C1":"","C2":"","C3":"","C4":"","C5":"","C6":"",
            "confidence_stated": auto_confidence,
            "notes": "Verify auto confidence." if auto_confidence else "",
        }
        existing[rid] = record
        save_results(existing)
        append_csv(record)
        session_ok += 1

        print(f"\n  {col('✓ DONE', BRIGHT_GREEN)}  "
              f"{col(f'{duration}s', BRIGHT_CYAN)}  │  "
              f"{col(f'{len(full_response):,} chars', WHITE)}  │  "
              f"{col(f'{speed:.0f} chars/s', DIM)}"
              f"{f'  │  Confidence: {auto_confidence}/100' if auto_confidence else ''}")

        done += 1
        elapsed_total = time.time()-t_start
        print(f"\n  {bar(done, total, 35, eta_str(done, total, elapsed_total))}")
        print(f"  {col('Session:', DIM)} {col(str(session_ok), BRIGHT_GREEN)} ok  "
              f"{col(str(session_err), BRIGHT_RED)} errors  │  "
              f"{col('Total saved:', DIM)} {col(str(len(existing)), WHITE)}")

    reconcile_csv(existing)

    total_time = round(time.time()-t_start, 1)
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
    print(f"\n  {col('Next step:', BOLD, YELLOW)} Open CSV and fill R1-R6 and C1-C6.")
    print(f"  {col('Then run:', BOLD, YELLOW)} python score.py")
    print(hr("═") + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {col('Interrupted — all completed runs are saved.', YELLOW)}\n")
        sys.exit(0)