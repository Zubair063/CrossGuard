# CrossGuard: LLM-based Cross-Language Attack Detection

This project uses LLM (Large Language Model) to identify and annotate cross-language attacks (CLA) in Rust-C FFI code.

## Prerequisites

- Python 3.7+
- OpenAI API key

## Installation

### 1. Install Required Python Libraries

```bash
pip install -r requirements_llm.txt
```

### 2. Install Tree-sitter Language Repositories

The parser requires tree-sitter language grammars. Install them via npm:

```bash
npm install tree-sitter-rust tree-sitter-c
```

Alternatively, if you have the repositories cloned locally, ensure they're in your current directory or adjust paths in `build_language.py`.

### 3. Build Tree-sitter Language Library

Before running the parser, you need to build the tree-sitter language library for Rust and C:

```bash
python3 build_language.py
```

This will create `build/my-languages.so` which is required by `parser.py`.

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

### Step 1: Parse Source Code

Extract function definitions and metadata from Rust/C source files:

**For all_attack testset:**
```bash
python3 parser.py \
  --src testsets/all_attack \
  --rust-out parser_output/all_attack_rust.json \
  --c-out parser_output/all_attack_c.json
```

**For author_code testset:**
```bash
python3 parser.py \
  --src testsets/author_code \
  --rust-out parser_output/author_code_rust.json \
  --c-out parser_output/author_code_c.json
```

### Step 2: Run LLM Attack Annotator

Analyze code using OpenAI API to identify and classify attacks:

**For C code:**
```bash
python3 llm_attack_annotator.py \
  --parser-json parser_output/all_attack_c.json \
  --code testsets/all_attack/all_attacks.c \
  --language c \
  --max-funcs 150
```

**For Rust code:**
```bash
python3 llm_attack_annotator.py \
  --parser-json parser_output/all_attack_rust.json \
  --code testsets/all_attack/all_attacks.rs \
  --language rust \
  --max-funcs 150
```

**Output files:**
- Annotated code: `llm_output/all_attacks_annotated.c` (or `all_attacks_annotated.rs`)
- CSV predictions: `llm_output/all_attacks_annotations.csv` (for C) or `llm_output/all_attacks_annotations.csv` (for Rust, based on input filename)

**Optional arguments:**
- `--api-key`: Override environment variable (if not set)
- `--model`: Specify OpenAI model (default: `gpt-4o-mini`)
- `--max-funcs`: Number of functions per batch (default: 20)
- `--output`: Custom output path for annotated code
- `--csv-output`: Custom output path for CSV report

### Step 3: Evaluate Model Performance

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
├── parser.py                    # Code parser (extracts functions)
├── llm_attack_annotator.py      # LLM-based attack classifier
├── evaluate_llm_annotations.py  # Performance evaluator
├── build_language.py           # Build tree-sitter language library
├── parser_output/              # Parser JSON outputs
├── llm_output/                 # LLM annotations and predictions
├── testsets/                   # Test datasets
│   ├── all_attack/            # All attack variants
│   └── author_code/           # Author's original code
└── build/                      # Compiled tree-sitter library
```

## Troubleshooting

**Error: Language .so not found**
- Run `python3 build_language.py` first

**Error: OpenAI API key not provided**
- Set `OPENAI_API_KEY` environment variable or use `--api-key` flag

**Error: Quota exceeded (429)**
- Check your OpenAI account billing and quota limits

**Error: ModuleNotFoundError**
- Install missing dependencies: `pip install tree-sitter openai`
- For tree-sitter language grammars: `npm install tree-sitter-rust tree-sitter-c`

