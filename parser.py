#!/usr/bin/env python3
"""
Improved parser that extracts complete function definitions and attack-relevant patterns
for better LLM-based attack identification.
"""

import os
import json
import argparse
import re
from tree_sitter import Language, Parser

# ---------------- Config ----------------
DEFAULT_LANG_SO = os.path.join(os.getcwd(), "build", "my-languages.so")
CONTEXT_LINES = 5  # lines above/below snippet to include for context

# Attack-relevant patterns
C_ATTACK_PATTERNS = [
    re.compile(r'\bfree\s*\('),  # Memory deallocation
    re.compile(r'\bmalloc\s*\('),  # Memory allocation
    re.compile(r'\[.*\]\s*='),  # Array indexing/writing
    re.compile(r'\*\w+\s*='),  # Pointer dereference and write
    re.compile(r'get_attack\s*\('),  # Attack function call
]

RUST_ATTACK_PATTERNS = [
    re.compile(r'\bunsafe\b'),
    re.compile(r'extern\s*"C"'),
    re.compile(r'\btransmute\b'),
    re.compile(r'\bas\s+\*(?:const|mut)\b'),
    re.compile(r'\.as\s+[iu]\d+'),  # Type casting to integers
    re.compile(r'get_attack\s*\('),
]

# ---------------- Helpers ----------------
def read_file_lines(path):
    with open(path, 'r', encoding='utf8', errors='replace') as f:
        return f.read().splitlines()

def get_context(lines, start_line, end_line, context=CONTEXT_LINES):
    # start_line & end_line are 1-indexed
    s = max(0, start_line - 1 - context)
    e = min(len(lines), end_line + context)
    return "\n".join(lines[s:e])

def node_text_bytes(bytestr, node):
    return bytestr[node.start_byte:node.end_byte].decode('utf8', errors='replace')

def extract_function_name_from_code(code, is_rust=False):
    """Extract function name from function code."""
    if is_rust:
        match = re.search(r'(?:pub\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn\s+(\w+)\s*\(', code)
    else:
        match = re.search(r'(?:static\s+)?(?:inline\s+)?(?:\w+\s+)*(\w+)\s*\(', code)
    return match.group(1) if match else None

# ---------------- Rust extraction (tree-sitter) ----------------
def extract_from_rust(path, rust_lang):
    parser = Parser(rust_lang)
    with open(path, 'rb') as f:
        source = f.read()
    tree = parser.parse(source)
    root = tree.root_node

    lines = source.decode('utf8', errors='replace').splitlines()
    items = []
    seen_functions = set()
    
    # Traverse AST
    stack = [root]
    while stack:
        node = stack.pop()
        t = node.type

        # Extract complete function definitions
        if t == 'function_item':
            code = node_text_bytes(source, node)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            
            func_name = extract_function_name_from_code(code, is_rust=True)
            if func_name:
                key = ('function', func_name, start_line)
                if key not in seen_functions:
                    seen_functions.add(key)
                    items.append({
                        "file": path,
                        "type": "function",
                        "function_name": func_name,
                        "start_line": start_line,
                        "end_line": end_line
                    })

        # Extract extern "C" blocks (FFI declarations)
        elif t == 'foreign_mod_item' or t == 'extern_item':
            code = node_text_bytes(source, node)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            
            items.append({
                "file": path,
                "type": "extern_block",
                "start_line": start_line,
                "end_line": end_line
            })

        # Extract unsafe blocks
        elif t == 'unsafe_block':
            code = node_text_bytes(source, node)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            
            items.append({
                "file": path,
                "type": "unsafe_block",
                "start_line": start_line,
                "end_line": end_line
            })

        # Push children
        for c in reversed(node.children):
            stack.append(c)

    return items

# ---------------- C extraction (improved) ----------------
def extract_from_c(path, c_lang):
    """Extract complete function definitions from C code using tree-sitter."""
    parser = Parser(c_lang)
    with open(path, 'rb') as f:
        source = f.read()
    tree = parser.parse(source)
    root = tree.root_node

    lines = source.decode('utf8', errors='replace').splitlines()
    items = []
    seen_functions = set()
    
    # Traverse AST
    stack = [root]
    while stack:
        node = stack.pop()
        t = node.type

        # Extract complete function definitions
        if t == 'function_definition':
            code = node_text_bytes(source, node)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            
            func_name = extract_function_name_from_code(code, is_rust=False)
            if func_name:
                key = ('function', func_name, start_line)
                if key not in seen_functions:
                    seen_functions.add(key)
                    items.append({
                        "file": path,
                        "type": "function",
                        "function_name": func_name,
                        "start_line": start_line,
                        "end_line": end_line
                    })

        # Extract function declarations (extern functions)
        elif t == 'declaration':
            code = node_text_bytes(source, node)
            # Check if it's a function declaration
            if 'extern' in code.lower() or '(' in code and ')' in code:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                
                func_name = extract_function_name_from_code(code, is_rust=False)
                if func_name:
                    items.append({
                        "file": path,
                        "type": "function_declaration",
                        "function_name": func_name,
                        "start_line": start_line,
                        "end_line": end_line
                    })

        # Push children
        for c in reversed(node.children):
            stack.append(c)

    return items

# ---------------- Main CLI ----------------
def main():
    global CONTEXT_LINES
    ap = argparse.ArgumentParser(description="Parse Rust/C examples and extract complete functions for attack analysis")
    ap.add_argument('--src', required=True, help='Path to source folder')
    ap.add_argument('--langso', default=DEFAULT_LANG_SO, help='Path to build/my-languages.so')
    ap.add_argument('--rust-out', default='rust_snippets.json', help='Output JSON for Rust')
    ap.add_argument('--c-out', default='c_snippets.json', help='Output JSON for C')
    ap.add_argument('--context-lines', type=int, default=CONTEXT_LINES, help='Context lines around snippets')
    args = ap.parse_args()

    CONTEXT_LINES = args.context_lines

    if not os.path.exists(args.langso):
        raise SystemExit(f"Language .so not found at {args.langso}. Build it first (build_language.py).")

    # Load languages
    try:
        from tree_sitter_languages import get_language, get_parser
        RUST_LANG = get_language('rust')
        C_LANG = get_language('c')
        print("[INFO] Using tree-sitter-languages package")
    except ImportError:
        # Fallback: use ctypes to load from .so file
        import ctypes
        lib = ctypes.CDLL(args.langso)
        
        try:
            tree_sitter_rust_fn = lib.tree_sitter_rust
            tree_sitter_rust_fn.restype = ctypes.c_void_p
            rust_ptr = tree_sitter_rust_fn()
            RUST_LANG = Language(rust_ptr)
        except (AttributeError, TypeError) as e:
            raise SystemExit(f"Could not load Rust language from {args.langso}. Error: {e}")
        
        try:
            tree_sitter_c_fn = lib.tree_sitter_c
            tree_sitter_c_fn.restype = ctypes.c_void_p
            c_ptr = tree_sitter_c_fn()
            C_LANG = Language(c_ptr)
        except (AttributeError, TypeError) as e:
            raise SystemExit(f"Could not load C language from {args.langso}. Error: {e}")

    rust_collected = []
    c_collected = []

    for root, dirs, files in os.walk(args.src):
        for fn in files:
            path = os.path.join(root, fn)
            if fn.endswith('.rs'):
                try:
                    rust_items = extract_from_rust(path, RUST_LANG)
                    if rust_items:
                        rust_collected.extend(rust_items)
                        func_count = len([i for i in rust_items if i['type'] == 'function'])
                        print(f"[RUST] extracted {len(rust_items)} items ({func_count} functions) from {path}")
                except Exception as e:
                    print(f"[WARN] Failed to parse Rust {path}: {e}")
            elif fn.endswith('.c') or fn.endswith('.h'):
                try:
                    c_items = extract_from_c(path, C_LANG)
                    if c_items:
                        c_collected.extend(c_items)
                        func_count = len([i for i in c_items if i['type'] == 'function'])
                        print(f"[C] extracted {len(c_items)} items ({func_count} functions) from {path}")
                except Exception as e:
                    print(f"[WARN] Failed to parse C {path}: {e}")

    # Sort outputs by file and line number
    rust_collected.sort(key=lambda r: (r['file'], r['start_line']))
    c_collected.sort(key=lambda r: (r['file'], r['start_line']))

    # Write JSON files
    with open(args.rust_out, 'w', encoding='utf8') as f:
        json.dump(rust_collected, f, indent=2)
    with open(args.c_out, 'w', encoding='utf8') as f:
        json.dump(c_collected, f, indent=2)

    print(f"\n[DONE] Wrote {len(rust_collected)} rust items -> {args.rust_out}")
    print(f"[DONE] Wrote {len(c_collected)} c items   -> {args.c_out}")
    
    # Print statistics
    rust_functions = [i for i in rust_collected if i['type'] == 'function']
    c_functions = [i for i in c_collected if i['type'] == 'function']
    print(f"\n[STATS] Rust: {len(rust_functions)} functions extracted")
    print(f"[STATS] C: {len(c_functions)} functions extracted")


if __name__ == "__main__":
    main()

