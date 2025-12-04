#!/usr/bin/env python
from tree_sitter import Language

# Build a shared parser library that includes Rust and C
Language.build_library(
    'build/my-languages.so',
    [
        'tree-sitter-rust',
        'tree-sitter-c'
    ]
)

print("✅ Successfully built 'build/my-languages.so'")
