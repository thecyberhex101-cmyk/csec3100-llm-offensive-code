# CSEC3100 Experiment Pipeline

## Setup
1. Put all .c sample files in the `samples/` folder
2. Run `python check_models.py` to confirm Ollama has all four models
3. Run `python run_experiment.py` to start the experiment

## What it does automatically
- Loads every .c file from `samples/`
- Runs each sample on every model under every condition
- Times every response
- Saves responses to `results/all_responses.json` (full text)
- Saves responses to `results/all_responses.csv` (for scoring)
- Retries incomplete/failed responses and only marks completed responses as done
- Auto-resumes if interrupted — skips already-completed runs
- Reconciles the CSV from JSON on startup/end and preserves scores already entered
- Extracts clearly labelled confidence ratings as candidates; verify them before scoring

`duration_s` is end-to-end request time and can include Ollama model loading or
warm-up; it is not a pure token-generation measurement.

Keep the scoring CSV closed in Excel while the experiment is running. If Excel locks
the file, completed responses are still saved to JSON and the CSV is synchronized
when the file can be written again.

## After running
1. Open `results/all_responses.csv` in Excel
2. For each row fill in: R1 R2 R3 R4 R5 R6 C1 C2 C3 C4 C5 C6. Verify any automatically extracted `confidence_stated` value; leave it blank if the response does not state a clear numeric confidence.
3. Save the CSV
4. Run `python score.py` to compute all 15 metrics automatically

Rubric entries must be between 0 and 3. Rows without complete, valid rubric
scores are excluded. Brier scores are calculated only for rows with a valid
confidence score from 0 to 100. The TSI calculation compares only adjacent,
available L0-L5 levels from the non-FR ladder samples. Brier scoring treats
`S >= 60` as a successful answer, consistent with the scorer's binary threshold.

## Models expected
| Model | Ollama name |
|---|---|
| CodeLlama 7B | codellama:7b-instruct |
| Qwen2.5-Coder 7B | qwen2.5-coder:7b-instruct |
| DeepHat V1 7B | deephat |
| LLaMA 3.1 8B | llama3.1:8b-instruct |

## Conditions
- A: No hardware context
- B_rowhammer: Rowhammer physics prompt (clflush, DRAM disturbance)
- B_flushreload: Flush+Reload physics prompt (cache timing, victim access)

FR-* samples run all three conditions. All other samples run A and B_rowhammer.

## Files produced
- results/all_responses.json — full response text, all metadata
- results/all_responses.csv — one row per run, ready for scoring
- results/run_log.txt — timestamped log of every run
- results/metrics.json — computed after scoring with score.py
