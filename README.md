# CrossGuard: LLM-based Cross-Language Attack Detection

This project uses LLM (Large Language Model) to identify and annotate cross-language attacks (CLA) in Rust-C FFI code.

## Prerequisites

- Python 3.7+
- OpenAI API key

## Installation

### Install Required Python Libraries

```bash
pip install -r requirements_llm.txt
```

**Note:** The LLM annotator no longer requires tree-sitter or parser setup. It analyzes source code directly.

## Configuration

### Set OpenAI API Key

Set the `OPENAI_API_KEY` environment variable:

**Option 1: Temporary (current session only)**
```bash
export OPENAI_API_KEY="sk-your-openai-key-here"
```

**Option 2: Permanent (add to ~/.bashrc)**
```bash
echo 'export OPENAI_API_KEY="sk-your-openai-key-here"' >> ~/.bashrc
source ~/.bashrc
```

**Verify it's set:**
```bash
echo $OPENAI_API_KEY
```

## Usage

### Run LLM Attack Annotator

Analyze code using OpenAI API to identify and classify attacks. The tool analyzes source code directly without requiring parser output.

**For C code:**
```bash
python3 llm_attack_annotator.py \
  --code testsets/all_attack/all_attacks.c \
  --language c \
  --max-funcs 20
```

**For Rust code:**
```bash
python3 llm_attack_annotator.py \
  --code testsets/all_attack/all_attacks.rs \
  --language rust \
  --max-funcs 20
```

**With API key:**
```bash
export OPENAI_API_KEY="sk-your-api-key-here"
python3 llm_attack_annotator.py \
  --code testsets/all_attack/all_attacks.rs \
  --language rust
```

**Output files:**
- Annotated code: `llm_output/all_attacks_annotated.c` (or `all_attacks_annotated.rs`)
- CSV predictions: `llm_output/all_attacks_annotations.csv` (based on input filename)

**Optional arguments:**
- `--api-key`: Override environment variable (if not set)
- `--model`: Specify OpenAI model (default: `gpt-5.1`)
- `--max-funcs`: Number of functions per batch (default: 20)
- `--output`: Custom output path for annotated code
- `--csv-output`: Custom output path for CSV report
- `--no-annotate`: Skip generating annotated source file (CSV only)

**Note:** The `--parser-json` argument is deprecated and no longer required. The tool analyzes source code directly.

### Evaluate Model Performance

Compare LLM predictions against ground truth:

```bash
python3 evaluate_llm_annotations.py \
  --ground-truth testsets/all_attack/ground_truth_c_functions.csv \
  --predictions llm_output/all_attacks_annotations.csv
```

**For Rust:**
```bash
python3 evaluate_llm_annotations.py \
  --ground-truth testsets/all_attack/ground_truth_rust_functions.csv \
  --predictions llm_output/all_attacks_annotations.csv
```

(Note: The CSV filename depends on your input filename. If you used `all_attacks.rs`, it will be `all_attacks_annotations.csv`)

**Optional: Save filtered ground truth subset**
```bash
python3 evaluate_llm_annotations.py \
  --ground-truth testsets/all_attack/ground_truth_c_functions.csv \
  --predictions llm_output/all_attacks_annotations.csv \
  --save-subset testsets/all_attack/ground_truth_c_functions_predicted_subset.csv
```

The evaluator automatically restricts evaluation to only functions that appear in both ground truth and predictions.

## Attack Types

The system classifies functions into the following attack types:

- **0**: Safe (no attack)
- **1**: Rust Bounds Check Bypass
- **2**: Rust Lifetime Bypass (Use-After-Free / Double-Free)
- **3**: C/C++ Hardening Bypass (CFI / Shadow-Stack Bypass)
- **4**: Dynamic Bounds Corruption (Vec Metadata Attack)
- **5**: Intended Interaction Corruption (Callback Poisoning)

## Project Structure

```
CrossGuard/
├── llm_attack_annotator.py      # LLM-based attack classifier (main tool)
├── evaluate_llm_annotations.py  # Performance evaluator
├── llm_output/                 # LLM annotations and predictions
├── testsets/                   # Test datasets
│   ├── all_attack/            # All attack variants
│   └── author_code/           # Author's original code
└── requirements_llm.txt        # Python dependencies
```

## Troubleshooting

**Error: OpenAI API key not provided**
- Set `OPENAI_API_KEY` environment variable or use `--api-key` flag
- Example: `export OPENAI_API_KEY="sk-your-key-here"`

**Error: Quota exceeded (429)**
- Check your OpenAI account billing and quota limits
- Wait for quota reset or upgrade your plan

**Error: ModuleNotFoundError**
- Install missing dependencies: `pip install -r requirements_llm.txt`
- This installs `openai` package (tree-sitter is no longer required)

**Error: Model not found**
- Ensure you have access to the specified model (default: `gpt-5.1`)
- Use `--model` flag to specify a different model if needed

