from tree_sitter import Language, Parser

# Load compiled grammars
RUST = Language('build/my-languages.so', 'rust')
C    = Language('build/my-languages.so', 'c')

parser = Parser()
parser.set_language(RUST)

# Simple Rust code sample
code = b"""
extern "C" {
    fn vuln_fn(x: *mut i64);
}
unsafe fn rust_fn() {
    let mut y: i64 = 0;
    vuln_fn(&mut y);
}
"""

tree = parser.parse(code)
print(tree.root_node.sexp())
