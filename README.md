# Zero-to-Hired

## Overview

Zero-to-Hired is a small Streamlit and LangGraph demo that shows how prompt injection can affect an AI resume-review system. The app reads PDF resumes, summarizes them with an LLM, and then asks the model to rank the candidates.

The main security idea is that the resumes are untrusted input. Some of the PDFs include attack text like `ignore previous instructions`, `system override`, or fake reviewer notes. Those attacks try to make the model break its normal evaluation process.

This project compares:

- a vulnerable baseline
- input sanitization
- semantic guardrails
- different model behavior when protections are turned off

## How It Works

The app has two main steps:

1. `read_cvs` loads the resumes and creates summaries
2. `summary` uses those summaries to choose the best candidate

This matters because prompt injection can affect the system at more than one stage. A malicious resume might influence the summary step, the final ranking step, or both.

Important files:

- `main.py` handles the Streamlit interface
- `promptinjection.py` contains the main logic
- `config/config.yml` sets up NeMo Guardrails
- `config/disallowed.co` defines refusal patterns

## Defenses Added

### 1. Data Sanitization

The first defense happens when resumes are loaded. Each PDF page is checked with:

- `llm-guard`
- keyword and phrase matching

If suspicious text is found, that page is replaced with:

- `[REDACTED: potential prompt injection removed from resume text]`

This helps block obvious attacks before the model uses the resume content.

### 2. Semantic Guardrails

The second defense happens during the final evaluation step. NeMo Guardrails is used to catch override-style attacks that still make it into the model workflow.

If a bad pattern is detected, the system refuses to continue and returns:

- `Evaluation stopped: malicious instruction pattern detected in resume content. Untrusted data was ignored.`

## Why These Changes Helped

The main problem was that obvious attacks were not always being flagged, and guardrails alone were not enough. The fix was to use layered defense:

- sanitize suspicious resume text early
- treat resume content as data, not instructions
- apply guardrails again at the final decision step

This made the app better at catching direct attacks and reduced the chance that poisoned resume text would affect the final ranking.

## Model Comparison

The app also includes a baseline comparison mode. This runs the same workflow across multiple Groq-hosted models with protections turned off.

The point of this test is to show that model choice alone is not a full security solution. Some models handled obvious attacks better than others, but that did not remove the underlying architecture problem.

## How To Run

From the repository root:

```powershell
pip install -r data_poisoning\requirements.txt
streamlit run data_poisoning\main.py
```

If needed, you can also run:

```powershell
python -m streamlit run data_poisoning\main.py
```

Then:

- enter your `GROQ_API_KEY`
- choose a model
- turn sanitization and guardrails on or off
- upload PDFs or use the sample resumes in `data_poisoning/cvs`

## Main Takeaway

This project shows that prompt injection in document-based AI systems is a real risk. Better models can help sometimes, but they are not enough by themselves. A stronger approach is to combine input sanitization with output guardrails.

## Disclaimer

This project is for educational purposes only.
