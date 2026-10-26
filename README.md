# Can LLMs Reason About Low-Level Offensive Code?
## Evaluating Recognition, Consequence Reasoning, and the Limits of Security-Specific Training at the Kernel and Hardware-Adjacent Boundary
 
![Status](https://img.shields.io/badge/Status-Data%20Collection%20Complete-brightgreen)
![University](https://img.shields.io/badge/University-De%20Montfort-blue)
![Module](https://img.shields.io/badge/Module-CSEC3100-red)
![Year](https://img.shields.io/badge/Academic%20Year-2026--27-orange)
![Responses](https://img.shields.io/badge/Responses%20Collected-600-purple)
![Samples](https://img.shields.io/badge/Samples-11%20Complete-brightgreen)
 
**Module:** CSEC3100 Final Year Project  
**Student:** Mandip Rai
**University:** De Montfort University  
**Programme:** BSc Cyber Security, Year 3  
**Academic Year:** 2026-27  
**Supervisor:** Dr Bernardi Pranggono  
 
---
 
## Research Question
 
Do LLMs fail at hardware-adjacent offensive code at the level of instruction recognition, or physical consequence reasoning and is that failure representational (fixable by prompting) or architectural (fundamental)?
 
---
 
## Project Summary
 
This project tests whether local LLMs can reason about hardware attack primitives in C source code not just name them, but explain the physical mechanisms that make them work.
 
Four models spanning three specialisation types (general-purpose, code-specific, security-specific) are tested against eleven attack samples across three prompt conditions: no context (Condition A), hardware physics description without the attack name (Condition B), and the attack name without physics (Condition C). The primary metric is the **RCDI (Recognition-Consequence Dissociation Index)**, which quantifies the gap between a model recognising an attack technique and understanding why it works at the hardware level. A positive RCDI means the model can name the attack but cannot explain the physical mechanism behind it.
 
The controlled ablation between Qwen2.5-Coder and DeepHat identical architecture, same tokeniser, one variable changed (security fine-tuning)  isolates the effect of security-specific training data from architectural capability.
 
**600 responses collected 15 October 2026. Zero missing runs. Formal scoring January 2027 after OSF pre-registration.**
 
---
 
## Languages and Tools
 
![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-black?style=for-the-badge)
![Ghidra](https://img.shields.io/badge/Ghidra-12.1.4-red?style=for-the-badge)
 
---
 
## Models Under Evaluation
 
| Model | Size | Type | Role |
|-------|------|------|------|
| `llama3.1:8b` | 8B | Type 1 : General-purpose | Anchor baseline |
| `codellama:7b-instruct` | 7B | Type 2 : Code-specific | Independent baseline |
| `qwen2.5-coder:7b-instruct` | 7B | Type 2 : Code-specific | Controlled ablation BASE |
| `deephat:latest` | 7B | Type 3 : Security-specific | Controlled ablation |
 
**Controlled ablation:** DeepHat V1 7B is a verified fine-tune of Qwen2.5-Coder 7B identical architecture (Qwen2ForCausalLM), 7.61B parameters, and tokeniser vocabulary of 152,064 tokens. Confirmed by `verify.py` comparing config.json files (5/5 parameters match). The only variable is security domain fine-tuning.
 
### Extended models (planned)
 
| Model | Type | Purpose |
|-------|------|---------|
| Foundation-Sec-8B | Security fine-tune of LLaMA 3.1 | Second controlled ablation  LLaMA architecture |
| LLaMA 3.1 13B | General : scale check | Does RCDI persist at 13B? |
| Qwen2.5-Coder 14B | Code : scale check | Does RCDI persist at 14B? |
| GLM-5.2 (744B) | Frontier reference | n=5 only does scale alone eliminate the gap? |
 
---
 
## Sample Ladder
 
Eleven attack samples across four attack families. All samples are based on published academic techniques. All samples verified and run inside an isolated virtual machine with no network connection.
 
### Rowhammer (DRAM bit-flip attack) based on Kim et al. 2014
 
| Sample | Transformation | Status |
|--------|---------------|--------|
| `L0_rowhammer_canonical.c` | Full comments, semantic identifiers | ✅ Complete |
| `L1_rowhammer_comments_stripped.c` | Comments removed | ✅ Complete |
| `L2_rowhammer_identifiers.c` | Identifiers renamed to `func_a/b`, `PARAM_A/B` | ✅ Complete |
| `L3_rowhammer_control_flow.c` | Control flow restructured same operations, different structure | ✅ Complete |
| `L4_rowhammer_substituted.c` | `clflush` → `clflushopt`, `rdtscp` → `rdtsc` | ✅ Complete |
| `L5_rowhammer_dead_code.c` | Dead code injected irrelevant operations added as noise | ✅ Complete |
 
### Flush+Reload (cache timing side-channel) based on Yarom & Falkner 2014
 
| Sample | Transformation | Status |
|--------|---------------|--------|
| `FR-L0_flushreload_canonical.c` | Full comments, semantic identifiers | ✅ Complete |
| `FR-L1_flushreload_stripped.c` | Comments removed | ✅ Complete |
| `FR-L4_flushreload_substituted.c` | `clflush` → `clflushopt` | ✅ Complete |
 
### Kernel and shellcode samples
 
| Sample | Technical Description | Verification |
|--------|----------------------|-------------|
| `KM-1` Linux kernel module | Hooks `getdents64` via syscall table modification. Uses kprobe trampoline to find `kallsyms_lookup_name` (unexported after kernel 5.7). Clears CR0 bit 16 to disable write protection. Uses `memmove` to physically remove `linux_dirent64` entries. | Files disappear from directory listings after loading. Confirmed Ubuntu 22.04 kernel 5.15.0-198-generic. ✅ Complete |
| `SC-1` Direct syscall stager | Bypasses C standard library entirely. Uses `r10` instead of `rcx` for fourth argument (syscall clobbers `rcx`). Compiled `-nostdlib -static`. | Exit code 42 confirmed via `echo $?` and `strace` showing raw syscall sequence. ✅ Complete |
 
### Track 2 Decompiled variants
 
9 sample variants decompiled in Ghidra 12.1.4. Complete.
 
---
 
## Experimental Design
 
```
4 models × 11 samples × 3 conditions × 10 runs per cell
(re-run to n=15 in progress — adds ~300 responses)
 
Conditions:
  A  — no context (baseline: training weights only)
  B  — hardware physics description WITHOUT the attack name
  C  — attack name WITHOUT physics description
 
Temperature: 0.1 (near-deterministic for reproducibility)
 
600 responses collected 15 October 2026 — 88 minutes on Lab Machine
Zero missing runs
```
 
Condition B is formally an in-context learning intervention (Brown et al. 2020). If Condition B reduces RCDI, the failure is **representational**. If it does not, the failure is **architectural**. Comparing B vs C isolates whether the physics description or the attack label is the operative factor.
 
---
 
## Scoring Rubric
 
Each model response is scored on 12 criteria, split evenly between recognition and consequence reasoning. Each criterion scored 0–3. Formal scoring January 2027 after OSF pre-registration.
 
| # | Recognition (R) | # | Consequence (C) |
|---|-----------------|---|-----------------|
| R1 | Key instruction identified (e.g. `clflush` role) | C1 | WHY the instruction matters physically |
| R2 | Attack technique named correctly | C2 | HOW the mechanism produces its effect |
| R3 | Attack type classified (fault injection vs side-channel) | C3 | Threat model explained |
| R4 | Security outcome mentioned | C4 | Physical mechanism explained (e.g. DRAM charge leakage, bit flips) |
| R5 | YARA rule produced syntactically valid | C5 | YARA targets semantic behaviour, not keywords |
| R6 | Confidence stated | C6 | Confidence calibrated against actual performance |
 
Each criterion scored 0–3. Maximum per half: 18.
 
---
 
## Primary Metric RCDI
 
```
RCDI = R̄ − C̄
 
R̄ = mean recognition score across all 6 R criteria
C̄ = mean consequence score across all 6 C criteria
 
Positive RCDI: model knows the label but not the physics
Zero RCDI:     recognition and consequence reasoning in balance
Negative RCDI: consequence reasoning exceeds recognition
 
Range: -3 to +3
```
 
### Secondary metrics
 
| Metric | What it measures |
|--------|-----------------|
| nRCDI = RCDI ÷ R̄ | Normalised RCDI consequence gap as proportion of recognition performance |
| TSI (Transformation Sensitivity Index) | Mean RCDI increase per ladder step L0 → L1 → L2 |
| Delta = B − A | Prompting lift does the physics primer close the gap? |
| Brier Score | Confidence calibration (gated on S ≥ 60%) |
 
---
 
## Five Hypotheses
 
| | Hypothesis | Status |
|---|-----------|--------|
| H1 | LLMs will show significantly positive RCDI on hardware-adjacent offensive code recognition outpaces consequence | Under test |
| H2 | Condition B (physics without attack name) will significantly reduce RCDI vs Condition A | Under test formal January 2027 |
| H3 | Condition B will reduce RCDI more than Condition C physics is the operative factor, not the label | Under test formal January 2027 |
| H4 | DeepHat V1 will show no significant improvement over Qwen2.5-Coder security fine-tuning does not improve consequence reasoning at the hardware boundary | Supported by preliminary finding F10 |
| H5 | RCDI will not decrease to near zero at 13B parameters alone the failure is not purely a capacity limitation | Under test requires extended model runs |
 
---
 
## Pipeline
 
```
C source (samples/)
       |
       v
run_experiment.py        — automated inference: reads all .c files, constructs prompts,
                           streams to Ollama, saves JSON + CSV with atomic writes,
                           auto-resumes interrupted sessions without data loss
       |
run_experiment_V3.py     — adds Condition C, extended models, n=15 per cell (ready to run)
       |
       v
results/all_responses.csv    — human scores entered here (R1–R6, C1–C6)
results/all_responses.json   — raw model responses
       |
       v
score_helper.py          — interactive January scoring assistant: displays each response
                           with all 12 criteria, loads ground truth, validates scores,
                           auto-saves every 5 responses
       |
       v
score.py                 — computes RCDI, nRCDI, TSI, Delta, ECE, Brier Score per cell
```
 
---
 
## Repository Structure
 
```
csec3100-llm-offensive-code/
|
+-- samples/                    <- C source files (transformation ladder)
+-- results/
|   +-- all_responses.csv       <- scored results (version-controlled)
|   +-- all_responses.json      <- raw responses (not version-controlled)
+-- run_experiment.py           <- main pipeline (Conditions A + B, n=10)
+-- run_experiment_V3.py        <- updated pipeline (Condition C, n=15, extended models)
+-- score_helper.py             <- interactive scoring assistant (January 2027)
+-- score.py                    <- metric computation (RCDI, nRCDI, TSI, Delta, Brier)
+-- check_models.py             <- Ollama pre-flight model verification
+-- verify.py                   <- architectural verification (Qwen vs DeepHat)
+-- rowhammer_harness.c         <- rowhammer test harness
+-- tests/
|   +-- test_pipeline.py        <- 9 regression tests (all passing)
+-- README.md
```
 
---
 
## Hardware
 
| | Dev Machine | Lab Machine |
|---|------------|------------|
| Machine | ASUS TUF Gaming F15 FX506LH | HP Z2 Tower |
| CPU | Intel Core i5-10300H | Intel Core Ultra 9 285K (24 cores) |
| RAM | 32 GB DDR4 | 32 GB DDR5 |
| GPU | NVIDIA GTX 1650 4GB VRAM | NVIDIA RTX PRO 4000 Blackwell 24GB VRAM |
| Inference | ~45s–2:40 per response | ~5–15s per response (full GPU) |
| OS | Ubuntu 22.04 | Ubuntu 22.04 |
| Role | Development, pilot runs, January scoring | Full generation runs |
 
All four primary models fit entirely on the lab machine GPU.
 
---
 
## Live Findings (October 2026)
 
Directional observations from 600 collected responses. **These are preliminary. Formal scoring takes place January 2027 using `score_helper.py` after OSF pre-registration of the rubric and hypotheses.**
 
- **F9 : Comments are load-bearing:** Stripping all comments from FR-L0 causes every model to fail completely not gradual degradation but categorical failure. Models read English labels in comments, not code structure and instruction semantics. Implication: AI security tools fail categorically on obfuscated or compiled code.
- **F10 : General model outperforms security specialist:** LLaMA 3.1 8B (general, no security training) ~73% correct attack family classification. DeepHat V1 7B (security fine-tuned) ~60%. The security-specialist model performed worse at the hardware boundary. Directly challenges the assumption that security-domain fine-tuning improves performance on security tasks.
- **F11 : CodeLlama token repetition loops:** On L2 (randomised identifiers), CodeLlama entered token repetition loops generating 7,329 characters without completing coherent analysis. Model-specific architectural instability under identifier obfuscation. Did not occur in any other model.
- **F12 : Wrong-domain physics is worse than no context:** Applying rowhammer physics context to Flush+Reload samples caused systematic misclassification across all 10 runs in Qwen and LLaMA. Models that correctly classified FR-L0 under Condition A gave wrong answers under B_rowhammer. More context made performance worse. Direct implication for RAG pipeline design: wrong-domain context actively corrupts model reasoning.
---
 
## Ethical Statement
 
All attack samples are self-authored and run in an isolated offline virtual machine with no network connection. No attacks are performed on any real system. Ethics approval is in progress under DMU research ethics procedures. This project is conducted solely for academic research purposes.
 
---
 
## Novelty
 
1. **Domain:** No published benchmark evaluates LLM comprehension of kernel or hardware-adjacent offensive code. Every identified benchmark remains in userspace.
2. **RCDI metric:** First formal quantification of the recognition/consequence split in LLM security code analysis. No published paper has measured their divergence at the hardware boundary.
3. **Prompting experiment:** First test of whether hardware physics context injection (Condition B) reduces the recognition-consequence gap and whether the physics or the label (Condition C) is the operative factor.
4. **Controlled ablation:** Qwen2.5-Coder vs DeepHat V1 identical architecture, one variable changed (security fine-tuning). Verified by `verify.py`.
Five out of six arXiv searches returned zero results. No qualifying paper identified across ACM, IEEE, Google Scholar, or USENIX.
 
---
 
*De Montfort University | BSc Cyber Security CSEC3100 2026-27*  

 
