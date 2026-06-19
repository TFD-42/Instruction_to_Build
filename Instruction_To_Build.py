#!/usr/bin/env python3
"""
Extract code blocks from an instruction file without altering the code.
Filenames and paths are inferred from comments; Ollama is used only as a fallback.
"""

import argparse
import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

# Optional Ollama
try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
EXTENSION_MAP = {
    'py': 'py', 'python': 'py',
    'sh': 'sh', 'bash': 'sh', 'zsh': 'sh',
    'go': 'go',
    'rs': 'rs', 'rust': 'rs',
    'js': 'js', 'javascript': 'js',
    'json': 'json',
    'yaml': 'yaml', 'yml': 'yaml',
    'sql': 'sql',
    'html': 'html', 'css': 'css',
    'c': 'c', 'cpp': 'cpp', 'h': 'h',
    'java': 'java',
    'rb': 'rb',
    'toml': 'toml',
    'txt': 'txt',
}

# Regex for fenced blocks
BLOCK_RE = re.compile(r'```([a-zA-Z0-9_\-\.\+\#]+)\s*\n(.*?)\n```', re.DOTALL)

# Patterns for filename/path in comments
COMMENT_PATTERNS = [
    re.compile(r'^(#|//|--)\s*([\w\-\.]+\.[a-zA-Z0-9]+)\s*$'),          # # file.ext
    re.compile(r'^/\*\s*([\w\-\.]+\.[a-zA-Z0-9]+)\s*\*/$'),             # /* file.ext */
    re.compile(r'^(#|//|--)\s*(/[^ ]+)\s*$'),                           # # /path/to/file.ext
    re.compile(r'^/\*\s*(/[^ ]+)\s*\*/$'),                              # /* /path/to/file.ext */
]

# ----------------------------------------------------------------------
def normalize_line_endings(text: str) -> str:
    return text.replace('\r\n', '\n')

def get_extension(lang: str) -> str:
    return EXTENSION_MAP.get(lang.lower(), 'txt')

def extract_blocks(content: str) -> List[Tuple[str, str, int]]:
    """Return list of (language, code, index) starting at 1."""
    blocks = []
    for idx, match in enumerate(BLOCK_RE.finditer(content), start=1):
        lang = match.group(1).strip().lower()
        code = match.group(2)
        blocks.append((lang, code, idx))
    return blocks

def detect_filename_and_path(code: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (filename, directory) from comments or (None, None)."""
    lines = code.split('\n')[:10]
    for line in lines:
        stripped = line.lstrip()
        for pat in COMMENT_PATTERNS:
            m = pat.match(stripped)
            if m:
                candidate = m.group(2) if len(m.groups()) >= 2 else m.group(1)
                if '/' in candidate:
                    p = Path(candidate)
                    return p.name, str(p.parent) if p.parent != Path('.') else None
                else:
                    return candidate, None
    return None, None

def suggest_filename_with_ollama(code: str, lang: str, model: str) -> Optional[str]:
    """Ask Ollama for a filename (never changes the code)."""
    if not OLLAMA_AVAILABLE:
        return None
    prompt = (
        f"You are a helpful assistant. Given a code snippet in {lang}, "
        "suggest a suitable filename (with extension) for this file. "
        "Respond with only the filename, no extra text.\n\n"
        f"```{lang}\n{code[:1000]}\n```"
    )
    try:
        resp = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}])
        name = resp['message']['content'].strip().strip('"').strip("'")
        if '.' not in name:
            name += '.' + get_extension(lang)
        return name
    except Exception as e:
        logging.error(f"Ollama suggestion failed: {e}")
        return None

def build_plan(blocks, base_name, use_ollama=False, ollama_model='qwen2.5:7b'):
    plan = []
    for lang, code, idx in blocks:
        filename, directory = detect_filename_and_path(code)
        if not filename and use_ollama:
            suggested = suggest_filename_with_ollama(code, lang, ollama_model)
            if suggested:
                filename = suggested
        if not filename:
            ext = get_extension(lang)
            filename = f"{base_name}_{lang}_{idx}.{ext}"
            logging.warning(f"Block {idx}: using fallback name '{filename}'")
        if directory is None:
            directory = "."
        plan.append({
            'index': idx,
            'language': lang,
            'filename': filename,
            'directory': directory,
            'code': code,  # unchanged
        })
    return plan

def write_files(plan, output_root, dry_run=False):
    created = []
    for entry in plan:
        dirpath = output_root / entry['directory']
        filepath = dirpath / entry['filename']
        if dry_run:
            logging.info(f"[DRY RUN] Would write {filepath}")
            created.append(filepath)
            continue
        dirpath.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(entry['code'])
        logging.info(f"Written {filepath}")
        created.append(filepath)
    return created

def main():
    parser = argparse.ArgumentParser(description="Extract code blocks deterministically.")
    parser.add_argument('--path', required=True, help='Instruction file')
    parser.add_argument('--output-dir', default='./extracted_project', help='Output root')
    parser.add_argument('--ollama', action='store_true', help='Use Ollama for filename suggestions')
    parser.add_argument('--ollama-model', default='qwen2.5:7b', help='Ollama model')
    parser.add_argument('--dry-run', action='store_true', help='Simulate only')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(levelname)s: %(message)s')

    if args.ollama and not OLLAMA_AVAILABLE:
        logging.error("Ollama requested but library not installed.")
        return 1

    input_path = Path(args.path)
    if not input_path.exists():
        logging.error(f"File not found: {input_path}")
        return 1
    content = normalize_line_endings(input_path.read_text(encoding='utf-8'))

    blocks = extract_blocks(content)
    if not blocks:
        logging.warning("No code blocks found.")
        return 0
    logging.info(f"Found {len(blocks)} blocks.")

    plan = build_plan(blocks, input_path.stem, args.ollama, args.ollama_model)
    output_root = Path(args.output_dir)
    written = write_files(plan, output_root, args.dry_run)

    # Save plan
    plan_path = output_root / 'plan.json'
    if not args.dry_run:
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        with open(plan_path, 'w', encoding='utf-8') as f:
            json.dump(plan, f, indent=2)
        logging.info(f"Plan saved to {plan_path}")

    logging.info(f"Done. {len(written)} file(s) prepared.")
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())
