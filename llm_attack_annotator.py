"""
LLM-based Attack Annotator for C/Rust Code
Takes parser JSON output and source code, uses OpenAI API to identify and annotate unsafe functions with attack types.
Uses gpt-4o-mini model with specific prompt format for Rust-C FFI security analysis.
"""

import os
import json
import argparse
import csv
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from openai import OpenAI


@dataclass
class FunctionAnnotation:
    """Represents a function with attack annotation"""
    function_name: str
    attack_type: int  # 0-5, where 0 = safe, 1-5 = attack types


class LLMAttackAnnotator:
    """Uses OpenAI API to identify and annotate unsafe functions with attack types"""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        max_funcs_per_batch: int = 20,
    ):
        """
        Initialize the annotator with OpenAI API key
        
        Args:
            api_key: OpenAI API key. If None, will try to get from OPENAI_API_KEY env var
            model: OpenAI model to use (default: gpt-4o-mini)
            max_funcs_per_batch: Maximum number of functions to send to the LLM in one batch
        """
        if api_key is None:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key is None:
                raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY env var or pass --api-key")
        
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.max_funcs_per_batch = max_funcs_per_batch
        self.function_annotations: List[FunctionAnnotation] = []
    
    def load_parser_json(self, json_path: str) -> List[Dict]:
        """Load parser JSON file"""
        with open(json_path, 'r') as f:
            return json.load(f)
    
    def load_source_code(self, code_path: str) -> str:
        """Load source code file"""
        with open(code_path, 'r') as f:
            return f.read()
    
    def extract_all_functions_from_code(self, source_code: str, language: str) -> List[Dict]:
        """
        Extract all functions from source code for annotation
        
        Args:
            source_code: Full source code
            language: 'c' or 'rust'
        
        Returns:
            List of function information dictionaries
        """
        functions = []
        lines = source_code.split('\n')
        
        if language == 'c':
            # Pattern for C functions: return_type function_name(...)
            pattern = re.compile(r'^(void|int64_t|int|static\s+void|static\s+int64_t)\s+(\w+)\s*\(')
            for i, line in enumerate(lines, 1):
                match = pattern.search(line.strip())
                if match:
                    func_name = match.group(2)
                    # Find function end (simple heuristic: next function or end of file)
                    end_line = i
                    brace_count = 0
                    found_start = False
                    for j in range(i - 1, len(lines)):
                        if '{' in lines[j]:
                            found_start = True
                            brace_count += lines[j].count('{')
                        if '}' in lines[j]:
                            brace_count -= lines[j].count('}')
                        if found_start and brace_count == 0:
                            end_line = j + 1
                            break
                    functions.append({
                        'name': func_name,
                        'start_line': i,
                        'end_line': end_line,
                        'code': '\n'.join(lines[i-1:end_line])
                    })
        
        elif language == 'rust':
            # Pattern for Rust functions: fn function_name(...)
            pattern = re.compile(r'^(pub\s+)?(extern\s+"C"\s+)?fn\s+(\w+)')
            for i, line in enumerate(lines, 1):
                match = pattern.search(line.strip())
                if match:
                    func_name = match.group(3)
                    # Find function end
                    end_line = i
                    brace_count = 0
                    found_start = False
                    for j in range(i - 1, len(lines)):
                        if '{' in lines[j]:
                            found_start = True
                            brace_count += lines[j].count('{')
                        if '}' in lines[j]:
                            brace_count -= lines[j].count('}')
                        if found_start and brace_count == 0:
                            end_line = j + 1
                            break
                    functions.append({
                        'name': func_name,
                        'start_line': i,
                        'end_line': end_line,
                        'code': '\n'.join(lines[i-1:end_line])
                    })
        
        return functions
    
    def analyze_with_llm(self, parser_data: List[Dict], source_code: str, language: str) -> Tuple[str, List[FunctionAnnotation]]:
        """
        Use OpenAI API to analyze code and return annotated code + CSV.
        To improve LLM output quality and stay within context limits, this
        method only sends a subset (up to 20) of functions and their
        corresponding parsed entries to the model in a single call.
        
        Args:
            parser_data: List of parsed snippets from JSON
            source_code: Full source code
            language: 'c' or 'rust'
        
        Returns:
            Tuple of (annotated_code, function_annotations)
        """
        # Extract all functions from the source so we can build a smaller batch
        all_functions = self.extract_all_functions_from_code(source_code, language)

        if not all_functions:
            # Fallback to previous behavior if we couldn't parse functions
            batch_source_code = source_code
            batch_parser_data = parser_data
        else:
            # Limit to first N functions to keep the input focused
            max_n = max(1, int(self.max_funcs_per_batch))
            batch_functions = all_functions[:max_n]
            batch_func_names = {f["name"] for f in batch_functions}

            # Build code consisting only of the selected functions
            batch_source_code = "\n\n".join(f["code"] for f in batch_functions)

            # Filter parser JSON entries to only those functions
            # (parser_data entries may not all have function_name)
            filtered_parser = []
            for item in parser_data:
                fn = item.get("function_name")
                if fn is None or fn in batch_func_names:
                    filtered_parser.append(item)
            batch_parser_data = filtered_parser

        # Prepare prompt for OpenAI using the reduced batch
        prompt = self._build_analysis_prompt(batch_parser_data, batch_source_code, language)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Rust–C FFI security analysis assistant."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3
            )
            
            # Get the response text
            response_text = response.choices[0].message.content
            
            # Parse the response to extract annotated code and CSV
            annotated_code, csv_data = self._parse_llm_response(response_text)
            
            # Parse CSV data into FunctionAnnotation objects
            function_annotations = self._parse_csv_data(csv_data)
            
            return annotated_code, function_annotations
        
        except Exception as e:
            error_msg = str(e)
            print(f"\n{'='*60}")
            print("ERROR: OpenAI API Call Failed")
            print(f"{'='*60}")
            
            # Check for specific error types
            if "insufficient_quota" in error_msg or "429" in error_msg:
                print("\n❌ QUOTA ERROR: You have exceeded your OpenAI API quota.")
                print("\nSolutions:")
                print("1. Check your OpenAI account billing: https://platform.openai.com/account/billing")
                print("2. Add payment method or increase quota limits")
                print("3. Wait for your quota to reset (usually monthly)")
                print("4. Upgrade your OpenAI plan if needed")
                print("\nThe script will continue but without LLM annotations.")
            elif "401" in error_msg or "invalid_api_key" in error_msg.lower():
                print("\n❌ AUTHENTICATION ERROR: Invalid API key.")
                print("\nSolutions:")
                print("1. Verify your API key is correct")
                print("2. Check if the key has expired or been revoked")
                print("3. Get a new API key from: https://platform.openai.com/api-keys")
            elif "rate_limit" in error_msg.lower():
                print("\n❌ RATE LIMIT ERROR: Too many requests.")
                print("\nSolutions:")
                print("1. Wait a few minutes and try again")
                print("2. Reduce the number of concurrent requests")
            else:
                print(f"\nError details: {error_msg}")
                import traceback
                traceback.print_exc()
            
            print(f"\n{'='*60}\n")
            # Fallback: return original code with empty annotations
            return source_code, []
    
    def _build_analysis_prompt(self, parser_data: List[Dict], source_code: str, language: str) -> str:
        """Build the prompt for OpenAI API using the specified format"""
        
        # Limit parser data to avoid token limits and derive a small FFI summary
        limited_parser = parser_data[:50]
        parser_str = json.dumps(limited_parser, indent=2)

        ffi_functions = []
        extern_blocks = 0
        unsafe_blocks = 0
        for item in limited_parser:
            itype = item.get("type")
            fname = item.get("function_name")
            if itype in ("function_declaration", "extern_block") and fname:
                ffi_functions.append(fname)
            if itype == "extern_block":
                extern_blocks += 1
            if itype == "unsafe_block":
                unsafe_blocks += 1

        ffi_functions = sorted(set(ffi_functions))
        ffi_summary_lines = []
        if ffi_functions:
            ffi_summary_lines.append(
                "- FFI-relevant functions (declared for cross-language use): "
                + ", ".join(ffi_functions)
            )
        if extern_blocks:
            ffi_summary_lines.append(f"- Number of extern/FFI blocks in this file: {extern_blocks}")
        if unsafe_blocks:
            ffi_summary_lines.append(f"- Number of unsafe blocks (Rust only): {unsafe_blocks}")
        ffi_summary = "\n".join(ffi_summary_lines) if ffi_summary_lines else "None explicitly detected."

        # Limit source code to avoid token limits (keep it reasonable)
        source_code_limited = source_code[:8000] if len(source_code) > 8000 else source_code
        
        prompt = f"""You are a Rust–C FFI security analysis assistant.

Your input:

1. Raw {language.upper()} source code

2. A parsed version of the code (tree-sitter AST or similar)

Your output must include TWO parts:

A. Annotated code  

B. A CSV table listing each function and its detected attack type  

   - Attack types: {{1,2,3,4,5}}  

   - If no attack detected, use 0.

====================================================
ATTACK DEFINITIONS (for classification)
====================================================

IMPORTANT: These are **Cross-Language Attacks (CLA)**. They only apply when
there is a concrete interaction path between **Rust and C** through FFI
functions, extern declarations, or callback-style APIs. If a function is
purely local to one language and does not participate in such an FFI-based
data or control-flow exchange, classify it as **0 (Safe)**.

Attack 1 — Rust Bounds Check Bypass  

Spatial memory corruption where C performs OOB writes into Rust-owned memory.
This requires C to have a way to write into memory owned or later read by Rust
via FFI-exposed pointers, slices, or buffers.

Attack 2 — Rust Lifetime Bypass (Use-After-Free / Double-Free)  

C frees or invalidates Rust-owned memory and Rust later uses it.
This requires a cross-language lifetime mismatch: Rust gives C a pointer or
handle, C can free or invalidate it, and Rust later assumes it is still valid.

Attack 3 — C/C++ Hardening Bypass (CFI / Shadow-Stack Bypass)  

C corrupts its own stack frame via OOB writes and Rust later performs an indirect call using corrupted data.
This requires C to influence control-flow data (function pointers, return
addresses, vtables, etc.) that Rust will later use through FFI.

Attack 4 — Dynamic Bounds Corruption (Vec Metadata Attack)  

C mutates Rust Vec metadata (ptr, len, cap), breaking Rust's dynamic bounds checks.
This requires C to receive a pointer to a Rust Vec (or its fields) and to be
able to overwrite its metadata so that later Rust indexing appears safe but is
actually out-of-bounds.

Attack 5 — Intended Interaction Corruption (Callback Poisoning)  

C returns forged integers or pointers that Rust blindly interprets as function callbacks.
This requires an FFI callback or function-pointer style interaction where one
language trusts function pointers or IDs provided by the other.

====================================================
ANNOTATED CODE OUTPUT RULES
====================================================

For EACH function:

Insert a header annotation block:

/* ================================================
   Function: <function_name>
   Attack Classification: <Attack N or "0 — Safe">
   Reason: <1–3 lines, using code + AST>
   Risk Level: <Low|Medium|High>
   ================================================ */

Then output the ORIGINAL FUNCTION CODE (unchanged).

Only add comments; never rewrite or alter code.

Optional inline comments:

// SECURITY WARNING: <short explanation>

====================================================
CSV OUTPUT FORMAT (MANDATORY)
====================================================

After the annotated code, output a CSV with the following columns:

function_name,attack_type

Use:

- Attack numbers 1–5

- Use 0 if no known attack applies

Example:

user_set_array,3
safe_function,0
callback_provider,5

====================================================
FINAL OUTPUT FORMAT (MANDATORY)
====================================================

You MUST output in this exact order:

1. ===== BEGIN ANNOTATED CODE =====

<annotated code here>

2. ===== BEGIN CSV =====

function_name,attack_type
...

Do NOT include explanations outside of code comments.

Do NOT wrap the CSV in code fences unless asked.

Do NOT modify the input code except to insert comments.

Return ONLY the annotated code and the CSV exactly in the order above.

====================================================
INPUT DATA
====================================================

FFI context summary (derived from parser JSON and important for your reasoning):
{ffi_summary}

Raw {language.upper()} Source Code:
```{language}
{source_code_limited}
```

Parsed Code (Tree-sitter AST):
```json
{parser_str}
```

Now analyze the code and provide the annotated code and CSV as specified above.
"""
        return prompt
    
    def _parse_llm_response(self, response_text: str) -> Tuple[str, str]:
        """
        Parse LLM response to extract annotated code and CSV
        
        Args:
            response_text: Full response from LLM
        
        Returns:
            Tuple of (annotated_code, csv_data)
        """
        # Look for the delimiters
        annotated_start = response_text.find("===== BEGIN ANNOTATED CODE =====")
        csv_start = response_text.find("===== BEGIN CSV =====")
        
        if annotated_start == -1 or csv_start == -1:
            # Try alternative formats
            annotated_start = response_text.find("BEGIN ANNOTATED CODE")
            csv_start = response_text.find("BEGIN CSV")
        
        if annotated_start != -1 and csv_start != -1:
            # Extract annotated code
            annotated_code = response_text[annotated_start:csv_start].replace("===== BEGIN ANNOTATED CODE =====", "").strip()
            # Remove any markdown code fences
            annotated_code = re.sub(r'^```\w*\n', '', annotated_code, flags=re.MULTILINE)
            annotated_code = re.sub(r'\n```$', '', annotated_code, flags=re.MULTILINE)
            
            # Extract CSV
            csv_data = response_text[csv_start:].replace("===== BEGIN CSV =====", "").strip()
            # Remove any markdown code fences
            csv_data = re.sub(r'^```\w*\n', '', csv_data, flags=re.MULTILINE)
            csv_data = re.sub(r'\n```$', '', csv_data, flags=re.MULTILINE)
            
            return annotated_code, csv_data
        else:
            # Fallback: try to find CSV in the response
            # Look for CSV pattern
            csv_match = re.search(r'function_name,attack_type\s*\n(.*?)(?:\n\n|\Z)', response_text, re.DOTALL)
            if csv_match:
                csv_data = "function_name,attack_type\n" + csv_match.group(1).strip()
                # Assume everything before CSV is annotated code
                annotated_code = response_text[:response_text.find("function_name,attack_type")].strip()
                return annotated_code, csv_data
        
        # If we can't parse, return original response as annotated code and empty CSV
        print("Warning: Could not parse LLM response format. Returning full response as annotated code.")
        return response_text, "function_name,attack_type\n"
    
    def _parse_csv_data(self, csv_data: str) -> List[FunctionAnnotation]:
        """
        Parse CSV data into FunctionAnnotation objects
        
        Args:
            csv_data: CSV string with function_name,attack_type columns
        
        Returns:
            List of FunctionAnnotation objects
        """
        annotations = []
        
        # Parse CSV
        lines = csv_data.strip().split('\n')
        if len(lines) < 2:
            return annotations
        
        # Skip header
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            
            # Parse CSV line
            parts = line.split(',')
            if len(parts) >= 2:
                func_name = parts[0].strip()
                try:
                    attack_type = int(parts[1].strip())
                    if 0 <= attack_type <= 5:
                        annotations.append(FunctionAnnotation(
                            function_name=func_name,
                            attack_type=attack_type
                        ))
                except ValueError:
                    # Try to parse attack type from text
                    attack_text = parts[1].strip().lower()
                    if '1' in attack_text or 'bounds' in attack_text:
                        attack_type = 1
                    elif '2' in attack_text or 'lifetime' in attack_text or 'uaf' in attack_text:
                        attack_type = 2
                    elif '3' in attack_text or 'hardening' in attack_text:
                        attack_type = 3
                    elif '4' in attack_text or 'dynamic' in attack_text or 'vec' in attack_text:
                        attack_type = 4
                    elif '5' in attack_text or 'intended' in attack_text or 'callback' in attack_text:
                        attack_type = 5
                    else:
                        attack_type = 0
                    
                    annotations.append(FunctionAnnotation(
                        function_name=func_name,
                        attack_type=attack_type
                    ))
        
        return annotations
    
    def save_annotated_code(self, annotated_code: str, output_path: str):
        """Save annotated code to file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(annotated_code)
    
    def save_csv_report(self, function_annotations: List[FunctionAnnotation], output_path: str):
        """Save CSV report to file"""
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['function_name', 'attack_type'])
            for annotation in function_annotations:
                writer.writerow([annotation.function_name, annotation.attack_type])


def main():
    parser = argparse.ArgumentParser(
        description='LLM-based Attack Annotator for C/Rust Code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze Rust code with parser JSON (uses gpt-4o-mini by default)
  python llm_attack_annotator.py --parser-json parser_output/rust_all_attacks.json --code testsets/all_attacks.rs --language rust

  # Analyze C code with custom API key
  python llm_attack_annotator.py --parser-json parser_output/c_all_attacks.json --code testsets/all_attacks.c --language c --api-key sk-...

  # Specify custom output paths
  python llm_attack_annotator.py --parser-json parser_output/rust_all_attacks.json --code src/main.rs --language rust --output annotated_main.rs --csv-output main_annotations.csv
        """
    )
    
    parser.add_argument('--parser-json', type=str, required=True,
                       help='Path to parser JSON file (e.g., c_snippets.json or rust_snippets.json)')
    parser.add_argument('--code', type=str, required=True,
                       help='Path to source code file (C or Rust)')
    parser.add_argument('--language', type=str, choices=['c', 'rust'], required=True,
                       help='Programming language: c or rust')
    parser.add_argument('--api-key', type=str, default=None,
                       help='OpenAI API key (or set OPENAI_API_KEY env var)')
    parser.add_argument('--model', type=str, default='gpt-4o-mini',
                       help='OpenAI model to use (default: gpt-4o-mini)')
    parser.add_argument('--output', type=str, default=None,
                       help='Output path for annotated code (default: <code_file>_annotated.<ext>)')
    parser.add_argument('--csv-output', type=str, default=None,
                       help='Output path for CSV report (default: <code_file>_annotations.csv)')
    parser.add_argument('--no-annotate', action='store_true',
                       help='Skip generating annotated source file')
    parser.add_argument(
        '--max-funcs',
        type=int,
        default=20,
        help='Maximum number of functions to send to the LLM in one batch (default: 20)',
    )
    
    args = parser.parse_args()
    
    # Validate files exist
    if not os.path.exists(args.parser_json):
        print(f"Error: Parser JSON file not found: {args.parser_json}")
        return 1
    
    if not os.path.exists(args.code):
        print(f"Error: Source code file not found: {args.code}")
        return 1
    
    # Initialize annotator
    try:
        annotator = LLMAttackAnnotator(
            api_key=args.api_key,
            model=args.model,
            max_funcs_per_batch=args.max_funcs,
        )
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    
    print(f"Loading parser JSON: {args.parser_json}")
    parser_data = annotator.load_parser_json(args.parser_json)
    print(f"Loaded {len(parser_data)} snippets from parser")
    
    print(f"Loading source code: {args.code}")
    source_code = annotator.load_source_code(args.code)
    
    print("Analyzing with OpenAI API (gpt-4o-mini)...")
    annotated_code, function_annotations = annotator.analyze_with_llm(parser_data, source_code, args.language)
    annotator.function_annotations = function_annotations
    print(f"Identified {len(function_annotations)} functions with attack classifications")
    
    # Create llm_output directory if it doesn't exist
    output_dir = "llm_output"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save annotated code
    if not args.no_annotate:
        if args.output is None:
            base = os.path.basename(args.code)
            base, ext = os.path.splitext(base)
            args.output = os.path.join(output_dir, f"{base}_annotated{ext}")
        else:
            # If user provided output path, ensure it's in llm_output folder
            output_filename = os.path.basename(args.output)
            args.output = os.path.join(output_dir, output_filename)
        
        print(f"\nSaving annotated code: {args.output}")
        annotator.save_annotated_code(annotated_code, args.output)
        print(f"Annotated code saved to: {args.output}")
    
    # Save CSV report
    if args.csv_output is None:
        base = os.path.basename(args.code)
        base, _ = os.path.splitext(base)
        args.csv_output = os.path.join(output_dir, f"{base}_annotations.csv")
    else:
        # If user provided CSV path, ensure it's in llm_output folder
        csv_filename = os.path.basename(args.csv_output)
        args.csv_output = os.path.join(output_dir, csv_filename)
    
    print(f"\nSaving CSV report: {args.csv_output}")
    annotator.save_csv_report(function_annotations, args.csv_output)
    print(f"CSV report saved to: {args.csv_output}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("ATTACK CLASSIFICATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total Functions Analyzed: {len(function_annotations)}")
    
    # Count by attack type
    attack_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for annotation in function_annotations:
        attack_counts[annotation.attack_type] = attack_counts.get(annotation.attack_type, 0) + 1
    
    print(f"\nBy Attack Type:")
    print(f"  Safe (0): {attack_counts[0]}")
    print(f"  Attack 1 (Rust Bounds Check Bypass): {attack_counts[1]}")
    print(f"  Attack 2 (Rust Lifetime Bypass): {attack_counts[2]}")
    print(f"  Attack 3 (C/C++ Hardening Bypass): {attack_counts[3]}")
    print(f"  Attack 4 (Dynamic Bounds Corruption): {attack_counts[4]}")
    print(f"  Attack 5 (Intended Interaction Corruption): {attack_counts[5]}")
    
    print(f"\n{'='*60}")
    print("FUNCTION CLASSIFICATIONS")
    print(f"{'='*60}")
    for annotation in function_annotations:
        attack_label = f"Attack {annotation.attack_type}" if annotation.attack_type > 0 else "Safe (0)"
        print(f"  {annotation.function_name}: {attack_label}")
    
    return 0


if __name__ == "__main__":
    exit(main())

