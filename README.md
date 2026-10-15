# Can LLMs Reason About Low-Level Offensive Code?
## Evaluating Recognition, Consequence Reasoning, and the Limits of Security-Specific Training at the Kernel and Hardware-Adjacent Boundary

![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen)
![University](https://img.shields.io/badge/University-De%20Montfort-blue)
![Module](https://img.shields.io/badge/Module-CSEC3100-red)
![Year](https://img.shields.io/badge/Academic%20Year-2026--27-orange)

**Module:** CSEC3100 Final Year Project
**Student:** Mandip Rai
**University:** De Montfort University
**Programme:** BSc Cyber Security, Year 3
**Academic Year:** 2026-27

---

## Research Question

Do LLMs fail at hardware-adjacent offensive code at the level of instruction recognition, or physical consequence reasoning - and is that failure representational (fixable by prompting) or architectural (fundamental)?

---

## Project Summary

This project tests whether local LLMs can reason about hardware attack primitives in C source code - not just name them, but explain the physical mechanisms that make them work.

Four models spanning three specialisation types (general-purpose, code-specific, security-specific) are tested against a transformation ladder of offensive C samples under two conditions: no context (Condition A) and a hardware-physics primer (Condition B). The primary metric is the **RCDI (Recognition-Consequence Dissociation Index)**, which quantifies the gap between a model recognising an attack technique and understanding why it works at the hardware level. A positive RCDI means the model can name the attack but cannot explain the physical mechanism behind it.

The controlled ablation between Qwen2.5-Coder and DeepHat - identical architecture, same tokeniser, one security fine-tuned - isolates the effect of security-specific training data from architectural capability.

---

## Languages and Tools

![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-black?style=for-the-badge)
![VMware](https://img.shields.io/badge/VMware-607078?style=for-the-badge&logo=vmware&logoColor=white)

---

## Models Under Evaluation

| Model | Size | Type | Role |
|-------|------|------|------|
| `codellama:7b-instruct` | 7B | Type 2 - Code-specific | Independent baseline |
| `qwen2.5-coder:7b-instruct` | 7B | Type 2 - Code-specific | DeepHat base model |
| `deephat:latest` | 7B | Type 3 - Security-specific | Controlled ablation |
| `llama3.1:8b` | 8B | Type 1 - General-purpose | Anchor |

**Controlled ablation:** DeepHat-V1-7B is a verified fine-tune of Qwen2.5-Coder-7B - identical architecture, parameters, and tokeniser. Any difference in results between them isolates the effect of security-specific training data only.

---

## Sample Ladder

Two attack families, each as a transformation ladder of increasing obfuscation. All samples are functionally identical - only the surface representation changes.

### Rowhammer (DRAM bit-flip attack)

| Sample | Transformation | Status |
|--------|---------------|--------|
| `L0_rowhammer_canonical.c` | Full comments, semantic identifiers | Complete |
| `L1_rowhammer_comments_stripped.c` | Comments removed | Complete |
| `L2_rowhammer_identifiers.c` | Identifiers renamed to `func_a/b`, `PARAM_A/B` | Complete |
| `L3_rowhammer_control_flow.c` | Control flow restructured | Pending |
| `L4_rowhammer_substituted.c` | `clflush` to `clflushopt`, `rdtscp` to `rdtsc` | Pending |
| `L5_rowhammer_dead_code.c` | Dead code injected | Pending |

### Flush+Reload (cache timing side-channel)

| Sample | Transformation | Status |
|--------|---------------|--------|
| `FR-L0_flushreload_canonical.c` | Full comments, semantic identifiers | Complete |
| `FR-L1_flushreload_stripped.c` | Comments removed | Complete |
| `FR-L4_flushreload_substituted.c` | `clflush` to `clflushopt`, `rdtscp` to `rdtsc` | Complete |

### Pending primitives

| Sample | Layer | Status |
|--------|-------|--------|
| `KM-1` - kernel module (`getdents64` hook) | Ring 0 | Pending |
| `SC-1` - direct syscall stager | Userspace evasion | Pending |

---

## Experimental Design

```
4 models x 6 samples x up to 3 conditions x 10 runs per cell

Conditions:
  A             - no hardware context (baseline)
  B_rowhammer   - rowhammer DRAM physics primer (~200 words)
  B_flushreload - Flush+Reload cache physics primer (~200 words)

FR samples receive all three conditions.
Rowhammer samples receive A and B_rowhammer only.

Temperature: 0.1 (near-deterministic for reproducibility)
```

---

## Scoring Rubric

Each model response is scored on 12 criteria, split evenly between recognition and consequence reasoning:

| # | Recognition (R) | # | Consequence (C) |
|---|-----------------|---|-----------------|
| R1 | Key instruction identified | C1 | Why that instruction matters physically |
| R2 | Technique named correctly | C2 | How the technique produces its effect |
| R3 | Attack type classified | C3 | Threat model explained |
| R4 | Security outcome mentioned | C4 | Physical mechanism described |
| R5 | YARA rule produced | C5 | YARA targets semantics, not keyword signatures |
| R6 | Confidence stated | C6 | Confidence calibrated against actual performance |

Each criterion scored 0-3. Maximum per half: 18.

---

## Primary Metric - RCDI

```
RCDI = R_mean - C_mean

R_mean = mean recognition score across all 6 R criteria
C_mean = mean consequence score across all 6 C criteria

Positive RCDI: model recognises the attack but cannot explain the physical mechanism
Zero RCDI:     recognition and consequence reasoning in balance
```

### Secondary metrics

| Metric | What it measures |
|--------|-----------------|
| TSI (Transformation Sensitivity Index) | Mean RCDI increase per ladder step L0 to L1 to L2 |
| Delta = B minus A | Prompting lift - does the physics primer close the gap? |
| Brier score | Confidence calibration (gated on S >= 60%) |

---

## Four Hypotheses

| | Hypothesis | Status |
|---|-----------|--------|
| H1 | RCDI rises with transformation level - consequence drops faster than recognition | Under test |
| H2 | Condition B outperforms Condition A for hardware samples - prompting lift is real | Supported (live data) |
| H3 | Prompting lift is larger for hardware samples than userspace - layer-specific | Under test |
| H4 | DeepHat fails similarly to Qwen despite security fine-tuning | Confirmed |

---

## Pipeline

```
C source (samples/)
       |
       v
run_experiment.py  --> streams prompt to Ollama (local LLM)
       |               auto-resumes interrupted runs
       |               atomic JSON writes + retry logic
       v
results/all_responses.csv   <- human scores entered here (R1-R6, C1-C6)
results/all_responses.json  <- raw model responses (not version-controlled)
       |
       v
score.py  --> computes RCDI, TSI, Delta, Brier score per cell
```

---

## Repository Structure

```
csec3100-llm-offensive-code/
|
+-- samples/               <- C source files (transformation ladder)
+-- results/
|   +-- all_responses.csv  <- scored results (version-controlled)
+-- run_experiment.py      <- main pipeline runner
+-- score.py               <- metric computation
+-- check_models.py        <- Ollama model verification
+-- tests/
|   +-- test_pipeline.py   <- 9 regression tests (all passing)
+-- README.md
```

---

## Hardware

| | Laptop | Lab Machine |
|---|--------|------------|
| Machine | ASUS TUF Gaming F15 FX506LH | HP Z2 Tower G1i |
| CPU | Intel Core i5-10300H | Intel Core Ultra 9 285K (24 cores) |
| RAM | 32 GB DDR4 | 32 GB DDR5 |
| GPU | GTX 1650 4GB VRAM | NVIDIA RTX PRO 4000 Blackwell 24GB VRAM |
| Inference | ~45s-2:40 per response | ~5-15s per response (full GPU) |
| Role | Development, scoring | Full n=10 generation runs |

All four models fit entirely on the lab machine GPU.

---

## Live Findings (October 2026)

Eight findings from 15 initial runs (FR-L0 x CodeLlama, preliminary - formal scoring January 2027):

- **F1 - H4 confirmed:** All three models show RCDI approx +27 on Condition A regardless of specialisation type. Security fine-tuning makes no difference to hardware consequence reasoning.
- **F2 - H2 supported:** All models improve A to B when the attack name is provided. Delta approx +17 to +19.
- **F3 - Classification bridge gap:** With physics context, models correctly absorbed the hardware description but assigned the wrong attack name. Three different wrong names across three models.
- **F4 - Verbosity does not equal correctness:** Validates rubric scoring over cosine similarity as the primary metric.
- **F5 - Residual confusion:** RCDI did not reach zero even with the attack name explicitly provided.
- **F6 - Prompt contamination:** Rowhammer physics applied to Flush+Reload code made performance worse than no context in 2/3 models. Wrong-domain physics is actively harmful.
- **F7 - Model filtering differs:** Qwen filtered the irrelevant physics; CodeLlama destabilised; DeepHat accepted it uncritically.
- **F8 - Hallucination:** CodeLlama fabricated a function call inside an empty loop with a confident, structured response.

---

## Ethical Statement

All attack samples are self-authored and run in an isolated offline environment. No real systems are targeted. No attacks are performed on any live environment. Ethics approval is in progress under DMU research ethics procedures. This project is conducted solely for academic research purposes.

---

## Novelty

1. **Domain:** No published benchmark evaluates LLM comprehension of kernel and hardware-adjacent offensive code.
2. **RCDI metric:** First formal quantification of the recognition/consequence split in LLM security analysis.
3. **Prompting experiment:** First test of whether the failure is representational (fixable) or architectural (fundamental) at the hardware boundary.
4. **Controlled ablation:** Qwen2.5-Coder vs DeepHat - identical architecture, one variable (security fine-tuning).

---

*De Montfort University - BSc Cyber Security - CSEC3100 - 2026-27*
