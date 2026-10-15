"""
CSEC3100 — Model checker v2
Checks which models are installed, shows status, timing hints.
"""
import urllib.request, json, sys, os, time

# ANSI
if sys.platform == "win32": os.system("")
def col(t,*c): return "".join(c)+str(t)+"\033[0m"
BOLD="\033[1m"; DIM="\033[2m"; GREEN="\033[92m"; RED="\033[91m"
YELLOW="\033[93m"; CYAN="\033[96m"; WHITE="\033[37m"

MODELS = {
    "codellama:7b-instruct"      : ("codellama",  "Type 2 Code",     "Baseline",            "~3.8 GB"),
    "qwen2.5-coder:7b-instruct"  : ("qwen",       "Type 2 Code",     "DeepHat base",        "~4.7 GB"),
    "deephat"                    : ("deephat",     "Type 3 Security", "Controlled ablation", "~4.7 GB"),
    "llama3.1:8b-instruct"       : ("llama3",      "Type 1 General",  "Optional anchor",     "~4.9 GB"),
}

print(f"\n{col('CSEC3100 — Model Status Check', BOLD, CYAN)}\n")

# Check Ollama
try:
    urllib.request.urlopen("http://localhost:11434", timeout=5)
    print(col("  ✓ Ollama is running", GREEN))
except:
    print(col("  ✗ Ollama is not running", RED))
    print(col("    Start it: ollama serve", DIM))
    sys.exit(1)

# Get installed models
try:
    with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as r:
        data = json.loads(r.read())
    installed = {m["name"] for m in data.get("models", [])}
except:
    installed = set()

print(f"  {col('Installed model count:', BOLD)} {len(installed)}\n")
print(f"  {'Model':<35} {'Key':<12} {'Type':<20} {'Role':<24} {'Size':<10} Status")
print("  " + "─"*110)

all_ready = True
for model_name, (key, typ, role, size) in MODELS.items():
    found = any(model_name in m for m in installed)
    if not found: all_ready = False
    status = col("✓ installed", GREEN) if found else col("✗ missing", RED)
    pull   = "" if found else col(f"  → ollama pull {model_name}", DIM)
    print(f"  {model_name:<35} {key:<12} {typ:<20} {role:<24} {size:<10} {status}")
    if pull: print(f"  {'':35} {pull}")

print()

# Quick inference timing test
if any(any(k in m for m in installed) for k in ["deephat","codellama"]):
    test_model = next((m for m in installed if "deephat" in m or "codellama" in m), None)
    if test_model:
        print(f"  {col('Quick timing test on', BOLD)} {col(test_model, CYAN)}...")
        payload = json.dumps({
            "model":"deephat" if "deephat" in test_model else test_model,
            "prompt":"What is clflush?",
            "stream":False,
            "options":{"num_predict":50,"temperature":0.1}
        }).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type":"application/json"}
        )
        try:
            t0 = time.time()
            with urllib.request.urlopen(req, timeout=120) as r:
                json.loads(r.read())
            elapsed = round(time.time()-t0, 1)
            per_full = round(elapsed * 30, 0)  # scale to ~1500 token response
            print(f"  {col('✓', GREEN)} Short response: {col(f'{elapsed}s', CYAN)}")
            print(f"  {col('→', YELLOW)} Full analysis response estimate: {col(f'~{int(per_full)}s', CYAN)}")
            total_est = int(per_full * 4 * 11 * 2.5 * 10 / 3600)
            print(f"  {col('→', YELLOW)} Full experiment (n=10, 4 models) estimate: {col(f'~{total_est}h', CYAN)}")
        except Exception as e:
            print(f"  {col('Timing test failed:', RED)} {e}")

print()
if all_ready:
    print(col("  ✓ All models ready. Run: python run_experiment.py", GREEN, BOLD))
else:
    print(col("  Pull missing models above, then run: python run_experiment.py", YELLOW))
print()
