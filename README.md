# Instruction to Build – Code Extractor


# STILL ON BUILD


A deterministic Python script that extracts code blocks from an instruction file, infers file names and directory paths from embedded comments, and writes the files into a structured project folder. Ollama can be used as a fallback for filename suggestions when no comment‑based hint is found.

---

## Features

- **Extracts all fenced code blocks** (```` ```lang … ``` ````) from a text file.
- **Automatically detects filenames and directories** from the first few lines of each block – supports common comment styles (`#`, `//`, `--`, `/* … */`).
- **Falls back to language‑based naming** if no comment is present (e.g., `file_py_1.py`).
- **Optional Ollama integration** to generate intelligent filenames when no comment hint exists.
- **Preserves code exactly** – never modifies the extracted content.
- **Builds a complete project tree** with folders and files, plus a `plan.json` summary.
- **Dry‑run mode** to preview what would be written.

---

## Requirements

- Python 3.6 or later
- Optional: [Ollama](https://ollama.com/) (with a model like `qwen2.5:7b`) for AI‑based filename suggestions.

No external Python packages are required unless you enable Ollama – then you need the `ollama` Python library:

```bash
pip install ollama
```

---

## Installation

Clone the repository or download `Instruction_To_Build.py` to your local machine.

```bash
git clone https://github.com/yourusername/instruction-to-build.git
cd instruction-to-build
```

Make the script executable (Unix/Linux/macOS):

```bash
chmod +x Instruction_To_Build.py
```

---

## Usage

```bash
python Instruction_To_Build.py --path <instruction_file> [options]
```

### Required arguments

| Argument | Description |
|----------|-------------|
| `--path` | Path to the instruction file containing code blocks. |

### Optional arguments

| Argument | Description |
|----------|-------------|
| `--output-dir` | Root directory where extracted files will be written (default: `./extracted_project`). |
| `--ollama` | Enable Ollama for fallback filename suggestions (requires `ollama` package installed and Ollama service running). |
| `--ollama-model` | Ollama model to use (default: `qwen2.5:7b`). |
| `--dry-run` | Simulate the extraction and write operations without creating any files. |
| `--verbose` | Show detailed debug output. |

---

## How it Works

1. **Read** the instruction file and normalize line endings.
2. **Extract** all fenced code blocks using the regex ```` ```lang … ``` ````.
3. For each block, inspect the first 10 lines for comments that contain a filename or path (e.g., `# main.py`, `// /src/utils/helper.js`, `/* config.json */`).
4. If a comment matches:
   - The filename and directory (if any) are used.
5. If no comment is found **and** `--ollama` is enabled:
   - The script sends the code snippet to Ollama with a prompt to suggest a suitable filename.
   - The response is sanitised and used as the filename.
6. If still no filename is determined:
   - A fallback name is generated: `{base_name}_{lang}_{index}.{ext}` (e.g., `myfile_py_1.py`).
7. **Write** each file into the appropriate directory (creating folders as needed).
8. Save a `plan.json` file in the output directory that records every block’s metadata and the final filename/directory chosen.

---

## Example

Suppose you have an instruction file `project_instructions.md` with the following content:

````markdown
# My Project

## Backend
```python
# app.py
def main():
    print("Hello")
```

## Configuration
```json
// /config/settings.json
{
  "debug": true
}
```

## Utility
```bash
#!/bin/bash
# helper.sh
echo "Running..."
```
````

Running:

```bash
python Instruction_To_Build.py --path project_instructions.md --output-dir ./my_project
```

will produce:

```
my_project/
├── app.py
├── config/
│   └── settings.json
├── helper.sh
└── plan.json
```

The `plan.json` file contains the exact extraction plan with the original code and the chosen file paths.

If you enable Ollama:

```bash
python Instruction_To_Build.py --path project_instructions.md --ollama
```

then blocks without a comment hint will be sent to Ollama for a filename suggestion.

---

## Filename Detection Patterns

The script recognises these comment patterns in the first 10 lines of a code block:

| Comment style | Example |
|---------------|---------|
| `# filename.ext` | `# main.py` |
| `// filename.ext` | `// utils.js` |
| `-- filename.ext` | `-- config.sql` |
| `/* filename.ext */` | `/* data.json */` |
| `# /path/to/file.ext` | `# /src/main.go` |
| `// /path/to/file.ext` | `// /lib/helper.rs` |
| `/* /path/to/file.ext */` | `/* /etc/hosts */` |

If a path is given (contains `/`), the directory part is used and the filename is extracted.

---

## Logging

- By default, the script logs `INFO` messages (warnings and progress).
- Use `--verbose` to see `DEBUG` level logs, including which Ollama requests are being made.
- `--dry-run` shows what would be written without performing any file I/O.

---

## Error Handling

- If the input file does not exist, the script exits with an error.
- If Ollama is requested but the library is not installed, the script will log an error and exit.
- If Ollama fails (e.g., service not running), the script falls back to the default naming and logs a warning.

---

## License

This script is provided as open‑source under the MIT License. Feel free to use, modify, and distribute it.

---

## Contributing

Pull requests and issues are welcome. Please ensure that new features include tests and documentation.

---

*Happy building!* 🚀
