#!/usr/bin/env python3
"""CLAUDE.md @imports -> OpenCode `instructions`, for OpenCode (OpenRouter) sessions.

OpenCode reads the working directory's CLAUDE.md as plain text: it does not expand Claude Code's
`@path` imports. This prints `{"instructions": [...]}`: absolute paths of every file CLAUDE.md
imports (recursively, max 5 hops like Claude Code; relative to the importing file; `@~/…` =
home), plus the `.claude/rules/*.md` files and what they import. CLAUDE.md itself is left out —
OpenCode already loads it. (Skills need nothing: OpenCode scans the project's .claude/skills,
symlinks included, on its own.)

Only project files are used; ~/.claude is not (an OpenCode session never has one of its own).
An `@` inside a code span/block, one glued to a word (an email address) or one naming no
existing file is not an import. Usage: opencode-instructions.py <wd>   -> JSON on stdout
"""
import json, os, re, sys

MAX_DEPTH = 5
IMPORT = re.compile(r"(?<![\w@.])@((?:~/|\.{1,2}/|/)?[^\s`'\"()<>\[\]{}@]+)")


def imports(path):
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        return []
    text = re.sub(r"(?ms)^\s*(```|~~~).*?^\s*\1[^\n]*$", "", text)   # fenced code blocks
    text = re.sub(r"(`+).*?\1", "", text)                            # inline code spans
    base = os.path.dirname(path)
    out = []
    for m in IMPORT.finditer(text):
        ref = m.group(1).rstrip(".,;:!?*_")
        p = os.path.expanduser(ref) if ref.startswith("~/") else os.path.join(base, ref)
        p = os.path.realpath(p)
        if os.path.isfile(p):
            out.append(p)
    return out


def main():
    wd = os.path.realpath(sys.argv[1] if len(sys.argv) > 1 else os.getcwd())
    roots = []
    claude_md = os.path.join(wd, "CLAUDE.md")
    if os.path.isfile(claude_md):
        roots.append((os.path.realpath(claude_md), False))   # loaded by OpenCode itself
    rules = os.path.join(wd, ".claude", "rules")
    if os.path.isdir(rules):
        for dirpath, _, files in sorted(os.walk(rules, followlinks=True)):
            for f in sorted(files):
                if f.endswith(".md"):
                    roots.append((os.path.realpath(os.path.join(dirpath, f)), True))

    seen, order = set(), []
    def visit(path, include, depth):
        if path in seen:
            return
        seen.add(path)
        if include:
            order.append(path)
        if depth < MAX_DEPTH:
            for p in imports(path):
                visit(p, True, depth + 1)
    for path, include in roots:
        visit(path, include, 0)

    json.dump({"instructions": order}, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
