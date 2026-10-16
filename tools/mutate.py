# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 5
"""Tiny mutation tester: break the code one way at a time and see if the tests notice.

Runs on a temp copy of the project, so the real files are never touched.
"""
import argparse
import ast
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 30  # seconds per mutant; a hang counts as caught

CMP_SWAP = {
    ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
    ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
    ast.In: ast.NotIn, ast.NotIn: ast.In,
}
ATTR_SWAP = {
    "rstrip": "lstrip", "lstrip": "rstrip",
    "startswith": "endswith", "endswith": "startswith",
}
CALL_SWAP = {"any": "all", "all": "any"}

# Text-level mutations the AST pass can't express: (old, new, description).
# An entry whose `old` text isn't in the file is skipped with a message.
MANUAL = [
    ("re.fullmatch", "re.match", "fullmatch -> match (trailing-newline guard)"),
    ("[0-9]", r"\d", r"[0-9] -> \d (Unicode digits)"),
    ('"Known"', '"known"', "ransomware comparison: Known -> known"),
    ('",".join', '", ".join', "cwes separator , -> ', '"),
    ("%r", "%s", "log with %s instead of %r"),
        (".fullmatch(", ".match(", "fullmatch -> match (compiled pattern)"),
    ("re.ASCII", "0", "drop re.ASCII (Unicode digits)"),
    ("(?a)", "", "drop inline (?a) flag (Unicode digits)"),
]


class Mutator(ast.NodeTransformer):
    """With target=None it only lists mutation sites; with target=N it applies site N."""

    def __init__(self, target=None):
        self.target = target
        self.sites = []   # (lineno, description), in visit order
        self.skip = set() # ids of docstring nodes

    def hit(self, node, desc):
        self.sites.append((getattr(node, "lineno", 0), desc))
        return len(self.sites) - 1 == self.target

    def _docstring(self, node):
        b = node.body
        if (b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant)
                and isinstance(b[0].value.value, str)):
            self.skip.add(id(b[0].value))

    def visit_Module(self, node):
        self._docstring(node)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._docstring(node)
        return self.generic_visit(node)

    visit_ClassDef = visit_FunctionDef

    def visit_Compare(self, node):
        self.generic_visit(node)
        for i, op in enumerate(node.ops):
            new = CMP_SWAP.get(type(op))
            if new and self.hit(node, f"{type(op).__name__} -> {new.__name__}"):
                node.ops[i] = new()
        return node

    def visit_BoolOp(self, node):
        self.generic_visit(node)
        new = ast.Or if isinstance(node.op, ast.And) else ast.And
        if self.hit(node, f"{type(node.op).__name__} -> {new.__name__}"):
            node.op = new()
        return node

    def visit_UnaryOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Not) and self.hit(node, "remove 'not'"):
            return node.operand
        return node

    def visit_BinOp(self, node):
        self.generic_visit(node)
        new = {ast.Add: ast.Sub, ast.Sub: ast.Add}.get(type(node.op))
        if new and self.hit(node, f"{type(node.op).__name__} -> {new.__name__}"):
            node.op = new()
        return node

    def visit_Constant(self, node):
        if id(node) in self.skip:
            return node
        v = node.value
        if isinstance(v, bool):
            new = not v
        elif isinstance(v, (int, float)):
            new = v + 1
        elif isinstance(v, str):
            new = v[1:] if v else "_MUT"   # drop first char: breaks char sets, prefixes, separators
        else:
            return node
        if self.hit(node, f"constant {v!r} -> {new!r}"):
            return ast.copy_location(ast.Constant(new), node)
        return node

    def _negate(self, node, kind):
        self.generic_visit(node)
        if self.hit(node, f"negate {kind} condition"):
            node.test = ast.UnaryOp(ast.Not(), node.test)
        return node

    def visit_If(self, node):
        return self._negate(node, "if")

    def visit_While(self, node):
        return self._negate(node, "while")

    def visit_IfExp(self, node):
        return self._negate(node, "ternary")

    def visit_Return(self, node):
        self.generic_visit(node)
        v = node.value
        if (v is not None and not (isinstance(v, ast.Constant) and v.value is None)
                and self.hit(node, "return None")):
            node.value = ast.Constant(None)
        return node

    def visit_Continue(self, node):
        if self.hit(node, "continue -> pass"):
            return ast.copy_location(ast.Pass(), node)
        return node

    def visit_Break(self, node):
        if self.hit(node, "break -> pass"):
            return ast.copy_location(ast.Pass(), node)
        return node

    def visit_Expr(self, node):
        self.generic_visit(node)
        if isinstance(node.value, ast.Call) and self.hit(node, "remove call statement"):
            return ast.copy_location(ast.Pass(), node)
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        new = ATTR_SWAP.get(node.attr)
        if new and self.hit(node, f".{node.attr} -> .{new}"):
            node.attr = new
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        f = node.func
        if isinstance(f, ast.Name):
            if f.id in CALL_SWAP and self.hit(node, f"{f.id}() -> {CALL_SWAP[f.id]}()"):
                f.id = CALL_SWAP[f.id]
            elif f.id == "isinstance" and self.hit(node, "isinstance(...) -> True"):
                return ast.copy_location(ast.Constant(True), node)
        return node


def ast_sites(src):
    probe = Mutator()
    probe.visit(ast.parse(src))
    return probe.sites


def build(src, index):
    m = Mutator(index)
    tree = ast.fix_missing_locations(m.visit(ast.parse(src)))
    return ast.unparse(tree)


def run_tests(work, tests):
    # no .pyc files: a same-size edit within one second could otherwise reuse a stale one
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *tests],
            cwd=work, env=env, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return "timeout"
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", nargs="?", default="threatintel/sources.py")
    ap.add_argument("--tests", nargs="+", default=["tests"])
    ap.add_argument("--lines", help="only mutate lines A-B, e.g. 40-90")
    args = ap.parse_args()

    target = (ROOT / args.target).resolve()
    rel = target.relative_to(ROOT)
    src = target.read_text()
    src_lines = src.splitlines()
    lo, hi = (map(int, args.lines.split("-")) if args.lines else (0, 10**9))

    mutants = []  # (kind, payload, description, line)
    for i, (line, desc) in enumerate(ast_sites(src)):
        if lo <= line <= hi:
            mutants.append(("ast", i, desc, line))
    for old, new, desc in MANUAL:
        if old not in src:
            print(f"skip (text not in file): {desc}")
            continue
        line = src[: src.index(old)].count("\n") + 1
        if lo <= line <= hi:
            mutants.append(("text", src.replace(old, new), desc, line))

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for item in ("threatintel", "tests"):
            shutil.copytree(ROOT / item, work / item,
                            ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        shutil.copy(ROOT / "pytest.ini", work / "pytest.ini")
        copy = work / rel

        if run_tests(work, args.tests) != 0:
            sys.exit("baseline is not green: fix the tests first")
        copy.write_text(ast.unparse(ast.parse(src)))
        if run_tests(work, args.tests) != 0:
            sys.exit("unparse round-trip broke the baseline: the tool, not your code, is at fault")

        print(f"{len(mutants)} mutants (S = survived, . = caught)")
        survivors, crashed = [], 0
        for kind, payload, desc, line in mutants:
            copy.write_text(build(src, payload) if kind == "ast" else payload)
            result = run_tests(work, args.tests)
            if result == 0:
                survivors.append((line, desc))
                print("S", end="", flush=True)
            else:
                crashed += result != 1
                print(".", end="", flush=True)

    caught = len(mutants) - len(survivors)
    print(f"\n\n{caught}/{len(mutants)} caught ({crashed} by crash or timeout rather than a failing test)")
    for line, desc in survivors:
        text = src_lines[line - 1].strip() if 0 < line <= len(src_lines) else ""
        print(f"  SURVIVED line {line}: {desc}\n      {text}")
    sys.exit(1 if survivors else 0)


if __name__ == "__main__":
    main()
