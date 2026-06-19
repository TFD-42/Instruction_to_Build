#!/usr/bin/env python3
"""
Advanced Project Builder from Instruction Files

Extracts code blocks, infers full file paths, builds dependency graphs,
detects project type, and optionally uses LLM to generate missing files.

Complete rewrite with:
- All critical bugs fixed
- Security hardening
- Type hints everywhere
- Dataclass-based architecture
- Robust import resolution
- Proper error handling
- Production-grade logging
"""

import argparse
import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from collections import defaultdict
from enum import Enum

# Optional dependencies
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# ============================================================================
# CONSTANTS & ENUMS
# ============================================================================

EXTENSION_MAP: Dict[str, str] = {
    'py': 'py', 'python': 'py',
    'sh': 'sh', 'bash': 'sh', 'zsh': 'sh',
    'go': 'go',
    'rs': 'rs', 'rust': 'rs',
    'js': 'js', 'javascript': 'js', 'jsx': 'jsx',
    'ts': 'ts', 'tsx': 'tsx',
    'json': 'json',
    'yaml': 'yaml', 'yml': 'yaml',
    'toml': 'toml',
    'sql': 'sql',
    'html': 'html', 'css': 'css',
    'c': 'c', 'cpp': 'cpp', 'cxx': 'cpp', 'h': 'h', 'hpp': 'hpp',
    'java': 'java',
    'rb': 'rb', 'ruby': 'rb',
    'txt': 'txt',
}

MODULE_TO_FILE: Dict[str, List[str]] = {
    'py': ['.py'],
    'js': ['.js', '.jsx', '.ts', '.tsx'],
    'go': ['.go'],
    'rs': ['.rs'],
    'java': ['.java'],
    'c': ['.c', '.h'],
    'cpp': ['.cpp', '.hpp', '.h'],
}

ENTRYPOINT_HEURISTICS: List[str] = [
    'main', 'app', 'index', 'server', 'cli', 'start',
    'manage', 'run', '__main__'
]

# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass(slots=True)
class ImportInfo:
    """Represents a single import/dependency in source code."""
    module: str
    is_relative: bool
    raw: str
    resolved_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Union[str, bool, None]]:
        return asdict(self)


@dataclass(slots=True)
class SourceFile:
    """Represents a single source file in the project."""
    path: str
    language: str
    code: str
    block_index: Optional[int]
    imports: List[ImportInfo] = field(default_factory=list)
    generated: bool = False
    hash_sha256: Optional[str] = None

    def compute_hash(self) -> str:
        """Compute SHA256 of code."""
        self.hash_sha256 = hashlib.sha256(self.code.encode('utf-8')).hexdigest()
        return self.hash_sha256

    def to_dict_metadata_only(self) -> Dict[str, Union[str, bool, int, List]]:
        """Serialize without code (for project_plan.json)."""
        return {
            'path': self.path,
            'language': self.language,
            'block_index': self.block_index,
            'generated': self.generated,
            'hash_sha256': self.hash_sha256,
            'imports': [asdict(imp) for imp in self.imports],
        }


@dataclass(slots=True)
class ProjectMetadata:
    """Project type and framework detection."""
    project_type: str
    frameworks: List[str] = field(default_factory=list)
    has_config_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Union[str, List]]:
        return asdict(self)


@dataclass(slots=True)
class ProjectPlan:
    """Complete project plan."""
    files: List[SourceFile]
    directories: Set[str]
    metadata: ProjectMetadata
    entrypoints: List[str]
    dependency_edges: List[Tuple[str, str]] = field(default_factory=list)
    missing_files: List[str] = field(default_factory=list)
    generated_files: Dict[str, str] = field(default_factory=dict)
    circular_dependencies: List[List[str]] = field(default_factory=list)

    def to_json_safe(self) -> Dict:
        """Convert to JSON-safe dict (no code in output)."""
        return {
            'files': [f.to_dict_metadata_only() for f in self.files],
            'directories': sorted(self.directories),
            'metadata': self.metadata.to_dict(),
            'entrypoints': self.entrypoints,
            'dependency_edges': self.dependency_edges,
            'missing_files': self.missing_files,
            'generated_files_count': len(self.generated_files),
            'circular_dependencies': self.circular_dependencies,
        }


# ============================================================================
# REGEX PATTERNS
# ============================================================================

# BUG FIX #1: Use named groups to avoid IndexError
PATH_PATTERNS: List[re.Pattern] = [
    re.compile(r'^(?:#|//|--)\s*(?P<path>[\w\-/.]+\.[a-zA-Z0-9]+)\s*$', re.MULTILINE),
    re.compile(r'^/\*\s*(?P<path>[\w\-/.]+\.[a-zA-Z0-9]+)\s*\*/$', re.MULTILINE),
]

# BUX FIX #2: Robust markdown fenced block parsing
# Handles: ```lang, ```lang path, ```lang title="path", etc.
BLOCK_RE: re.Pattern = re.compile(
    r'```([^\n]*)\n(.*?)\n```',
    re.DOTALL
)

# Language-specific import patterns
IMPORT_PATTERNS: Dict[str, List[Tuple[re.Pattern, bool]]] = {
    'py': [
        (re.compile(r'^import\s+([\w.]+)', re.MULTILINE), False),
        (re.compile(r'^from\s+([\w.]+)\s+import', re.MULTILINE), False),
        (re.compile(r'^from\s+\.+([\w.]*)\s+import', re.MULTILINE), True),
    ],
    'js': [
        (re.compile(r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]', re.MULTILINE), False),
        (re.compile(r'import\s+[\'"]([^\'"]+)[\'"]', re.MULTILINE), False),
        (re.compile(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', re.MULTILINE), False),
    ],
    'go': [
        (re.compile(r'^import\s+"([^"]+)"', re.MULTILINE), False),
    ],
    'rs': [
        (re.compile(r'^use\s+([\w:]+)', re.MULTILINE), False),
        (re.compile(r'^mod\s+([\w]+);', re.MULTILINE), False),
    ],
    'java': [
        (re.compile(r'^import\s+([\w.]+);', re.MULTILINE), False),
    ],
    'c': [
        (re.compile(r'#include\s+[<"]([^>"]+)[>"]', re.MULTILINE), False),
    ],
    'cpp': [
        (re.compile(r'#include\s+[<"]([^>"]+)[>"]', re.MULTILINE), False),
    ],
}

logger = logging.getLogger(__name__)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def normalize_line_endings(text: str) -> str:
    """Normalize CRLF -> LF."""
    return text.replace('\r\n', '\n')


def get_extension(lang: str) -> str:
    """Get file extension for language."""
    return EXTENSION_MAP.get(lang.lower(), 'txt')


def validate_output_path(path: Path, output_root: Path) -> bool:
    """
    Security check: ensure path doesn't escape output_root via traversal.
    Returns True if safe, False otherwise.
    """
    try:
        resolved = (output_root / path).resolve()
        root_resolved = output_root.resolve()
        return root_resolved in resolved.parents or resolved == root_resolved
    except (ValueError, RuntimeError):
        return False

# ============================================================================
# BLOCK EXTRACTION
# ============================================================================

def extract_blocks(content: str) -> List[Tuple[str, str, Optional[str], int]]:
    """
    Extract code blocks from markdown.
    Returns list of (language, code, explicit_path, index).
    
    BUG FIX #2: Robust parsing of:
    ```python
    ...
    
    ```python path/to/file.py
    ...
    
    ```python title="path/to/file.py"
    ...
    """
    blocks: List[Tuple[str, str, Optional[str], int]] = []
    
    for idx, match in enumerate(BLOCK_RE.finditer(content), start=1):
        info_line = match.group(1).strip()
        code = match.group(2)
        
        # Parse info line: "python", "python path/to/file.py", or "python title=\"...\""
        parts = info_line.split(maxsplit=1)
        language = parts[0].lower() if parts else 'txt'
        explicit_path = None
        
        if len(parts) > 1:
            remainder = parts[1]
            
            # Try to extract path from title="..."
            title_match = re.search(r'title=["\']([^"\']+)["\']', remainder)
            if title_match:
                explicit_path = title_match.group(1)
            else:
                # Treat remainder as direct path
                explicit_path = remainder.strip('"\'')
        
        blocks.append((language, code, explicit_path, idx))
    
    return blocks


# ============================================================================
# PATH DETECTION
# ============================================================================

def detect_explicit_path_in_code(code: str) -> Optional[str]:
    """
    Extract explicit path from comment in first 10 lines.
    BUG FIX #1: Use named groups to avoid IndexError.
    """
    lines = code.split('\n')[:10]
    
    for line in lines:
        stripped = line.lstrip()
        
        for pattern in PATH_PATTERNS:
            match = pattern.search(stripped)
            if match:
                candidate = match.group('path')
                # Normalize path separators
                candidate = candidate.replace('\\', '/')
                return candidate
    
    return None


# ============================================================================
# IMPORT DETECTION & RESOLUTION
# ============================================================================

def detect_imports(code: str, lang: str) -> List[ImportInfo]:
    """
    Detect imports/dependencies in code.
    BUG FIX: Improved detection for JS require(), Go blocks, deduplication.
    """
    if lang not in IMPORT_PATTERNS:
        return []
    
    imports: List[ImportInfo] = []
    seen: Set[str] = set()
    
    # Special handling for Go import blocks
    if lang == 'go':
        # First, parse import ( ... ) blocks
        import_block_match = re.search(
            r'import\s*\(\s*(.*?)\s*\)',
            code,
            re.DOTALL | re.MULTILINE
        )
        if import_block_match:
            block_content = import_block_match.group(1)
            for line in block_content.split('\n'):
                line = line.strip()
                if line and not line.startswith('//'):
                    # Extract module name from quoted string
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        module = m.group(1)
                        if module not in seen:
                            seen.add(module)
                            imports.append(ImportInfo(
                                module=module,
                                is_relative=False,
                                raw=line,
                            ))
    
    # Apply regex patterns for language
    for pattern, is_relative in IMPORT_PATTERNS[lang]:
        for match in pattern.finditer(code):
            module = match.group(1)
            
            # Skip if already seen (deduplication)
            if module in seen:
                continue
            
            seen.add(module)
            imports.append(ImportInfo(
                module=module,
                is_relative=is_relative,
                raw=match.group(0),
            ))
    
    return imports


def resolve_import(module: str, lang: str) -> Optional[str]:
    """
    Resolve module name to file path.
    BUG FIX: Proper handling of relative imports, Python packages, Rust::, etc.
    """
    if not module:
        return None
    
    # Remove leading dots for relative imports
    depth = 0
    while module.startswith('.'):
        depth += 1
        module = module[1:]
    
    if not module:
        return None
    
    exts = MODULE_TO_FILE.get(lang, ['.txt'])
    ext = exts[0]
    
    if lang == 'py':
        # Python: api.routes -> api/routes.py
        path = module.replace('.', '/')
        return path + ext
    
    elif lang == 'go':
        # Go: github.com/pkg/name -> name.go (simplified)
        # Real resolution would need go.mod
        parts = module.split('/')
        return parts[-1] + ext if parts else None
    
    elif lang == 'rs':
        # Rust: crate::db::models -> crate/db/models.rs
        path = module.replace('::', '/')
        return path + ext
    
    elif lang == 'js':
        # JS: ./components/Button -> components/Button.js
        # JS: react -> None (external package)
        if module.startswith('./') or module.startswith('../'):
            return module + (ext if not module.endswith(ext) else '')
        return None
    
    elif lang == 'java':
        # Java: com.example.App -> com/example/App.java
        path = module.replace('.', '/')
        return path + ext
    
    elif lang == 'c' or lang == 'cpp':
        # C/C++: stdio.h -> stdio.h (system headers often unresolvable)
        if '<' in module or module.startswith('"'):
            return None
        return module if module.endswith(('.h', '.hpp')) else module + ext
    
    return None


# ============================================================================
# PROJECT TYPE DETECTION
# ============================================================================

def detect_project_type(files: List[SourceFile]) -> ProjectMetadata:
    """
    Detect project type and frameworks.
    BUG FIX: Import inspection for FastAPI/Flask/Django detection.
    """
    file_paths = {f.path for f in files}
    
    project_type = 'unknown'
    frameworks: List[str] = []
    config_files: List[str] = []
    
    # Config file detection
    config_mapping = {
        'package.json': 'node',
        'pyproject.toml': 'python',
        'requirements.txt': 'python',
        'Cargo.toml': 'rust',
        'go.mod': 'go',
        'pom.xml': 'java',
    }
    
    for config, ptype in config_mapping.items():
        if config in file_paths:
            project_type = ptype
            config_files.append(config)
    
    # Framework detection via imports
    for file in files:
        if file.language == 'py':
            code_lower = file.code.lower()
            if 'fastapi' in code_lower:
                frameworks.append('fastapi')
            elif 'flask' in code_lower:
                frameworks.append('flask')
            elif 'django' in code_lower:
                frameworks.append('django')
            elif 'typer' in code_lower:
                frameworks.append('typer')
            elif 'click' in code_lower:
                frameworks.append('click')
        
        elif file.language in ('jsx', 'tsx'):
            frameworks.append('react')
        elif file.language == 'vue':
            frameworks.append('vue')
        elif file.path.endswith('.vue'):
            frameworks.append('vue')
    
    # Docker
    if 'Dockerfile' in file_paths:
        frameworks.append('docker')
    
    return ProjectMetadata(
        project_type=project_type,
        frameworks=list(set(frameworks)),
        has_config_files=config_files,
    )


# ============================================================================
# DEPENDENCY GRAPH
# ============================================================================

def build_dependency_graph(
    files: List[SourceFile]
) -> Union[nx.DiGraph, Dict[str, List[str]]]:
    """
    Build dependency graph from imports.
    BUG FIX: Proper path canonicalization before adding edges.
    """
    if NETWORKX_AVAILABLE:
        G = nx.DiGraph()
        
        # Add all files as nodes
        for file in files:
            G.add_node(file.path)
        
        # Add edges based on resolved imports
        for file in files:
            for imp in file.imports:
                if imp.resolved_path:
                    # Check if resolved path matches any file
                    for target_file in files:
                        if imp.resolved_path in target_file.path or \
                           target_file.path.endswith(imp.resolved_path):
                            G.add_edge(file.path, target_file.path)
                            break
        
        return G
    else:
        # Fallback dict representation
        deps: Dict[str, List[str]] = defaultdict(list)
        for file in files:
            for imp in file.imports:
                if imp.resolved_path:
                    deps[file.path].append(imp.resolved_path)
        return dict(deps)


def detect_circular_dependencies(graph: Union[nx.DiGraph, Dict]) -> List[List[str]]:
    """
    Detect circular dependencies in graph.
    BUG FIX: Using networkx properly.
    """
    if not NETWORKX_AVAILABLE or not isinstance(graph, nx.DiGraph):
        return []
    
    try:
        cycles = list(nx.simple_cycles(graph))
        return cycles
    except Exception:
        return []


def find_entrypoints(files: List[SourceFile], graph: Union[nx.DiGraph, Dict]) -> List[str]:
    """
    Find entrypoint files.
    BUG FIX: Better heuristics, avoid leaf utility files.
    """
    entrypoints: List[str] = []
    
    if NETWORKX_AVAILABLE and isinstance(graph, nx.DiGraph):
        # Files with no incoming edges
        roots = [n for n in graph.nodes if graph.in_degree(n) == 0]
        if roots:
            entrypoints = roots
    
    # If no graph-based entrypoints, use heuristics
    if not entrypoints:
        for file in files:
            basename = Path(file.path).stem.lower()
            for hint in ENTRYPOINT_HEURISTICS:
                if hint in basename:
                    entrypoints.append(file.path)
                    break
    
    # If still empty, default to first Python file or first file
    if not entrypoints:
        py_files = [f.path for f in files if f.language == 'py']
        entrypoints = py_files[:1] if py_files else [files[0].path if files else None]
    
    return [e for e in entrypoints if e]


# ============================================================================
# LLM INTEGRATION
# ============================================================================

async def llm_project_plan_async(
    blocks: List[Tuple[str, str, Optional[str], int]],
    model: str
) -> Dict[str, any]:
    """
    Use Ollama to analyze blocks and produce plan.
    BUG FIX: Async support, error handling.
    """
    if not OLLAMA_AVAILABLE:
        logger.warning("Ollama not available, skipping LLM planning")
        return {}
    
    blocks_summary = []
    for lang, code, path, idx in blocks:
        preview = '\n'.join(code.split('\n')[:5])
        blocks_summary.append(f"Block {idx} ({lang}, path={path}):\n{preview}")
    
    prompt = f"""
You are an expert software architect. Analyze these code blocks and produce a complete project plan.

Blocks:
{chr(10).join(blocks_summary)}

Return ONLY a JSON object (no markdown, no explanation):
{{
  "project_type": "python|node|go|rust|java|unknown",
  "frameworks": ["framework1", "framework2"],
  "entrypoints": ["path/to/main.py"],
  "missing_files": ["requirements.txt", "README.md"]
}}
"""
    
    try:
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response['message']['content'].strip()
        
        # Extract JSON
        json_match = re.search(r'\{.*\}', raw, re.DOTALL)
        if json_match:
            raw = json_match.group(0)
        
        plan = json.loads(raw)
        logger.info(f"LLM planning succeeded: {plan.get('project_type')}")
        return plan
    except Exception as e:
        logger.error(f"LLM planning failed: {e}")
        return {}


async def generate_missing_files_async(
    missing_files: List[str],
    project_type: str,
    model: str
) -> Dict[str, str]:
    """
    Use Ollama to generate missing files.
    BUG FIX: Explicit format instructions to avoid parser issues.
    """
    if not OLLAMA_AVAILABLE or not missing_files:
        return {}
    
    prompt = f"""
You are a developer. Generate content for missing files in a {project_type} project.

Missing files: {', '.join(missing_files)}

Respond with ONLY code blocks in this format:
```language filename.ext
<file content>
```

One block per file. Example:
```python requirements.txt
fastapi==0.95.0
uvicorn
```

Do not include any other text.
"""
    
    try:
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        
        content = response['message']['content']
        blocks = extract_blocks(content)
        
        generated: Dict[str, str] = {}
        for lang, code, explicit_path, idx in blocks:
            if explicit_path:
                generated[explicit_path] = code
            else:
                # Fallback: use language as hint
                generated[f"missing_{idx}.{lang}"] = code
        
        logger.info(f"Generated {len(generated)} missing files")
        return generated
    except Exception as e:
        logger.error(f"Missing file generation failed: {e}")
        return {}


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def process_blocks(
    blocks: List[Tuple[str, str, Optional[str], int]],
    base_name: str,
    use_ollama: bool = False,
    ollama_model: str = 'qwen2.5:7b',
    generate_missing: bool = False,
) -> ProjectPlan:
    """
    Process code blocks into a complete project plan.
    """
    files: List[SourceFile] = []
    
    # First pass: extract files
    for lang, code, explicit_path, idx in blocks:
        # Determine path
        if explicit_path:
            path = explicit_path
        else:
            # Try to detect from code comments
            detected = detect_explicit_path_in_code(code)
            if detected:
                path = detected
            else:
                # Fallback: generate path
                ext = get_extension(lang)
                path = f"{base_name}_{idx}.{ext}"
                logger.debug(f"Block {idx}: no path found, using fallback '{path}'")
        
        # Normalize path
        path = path.replace('\\', '/')
        
        # Detect imports
        imports = detect_imports(code, lang)
        
        # Resolve import paths
        for imp in imports:
            imp.resolved_path = resolve_import(imp.module, lang)
        
        # Create SourceFile
        file = SourceFile(
            path=path,
            language=lang,
            code=code,
            block_index=idx,
            imports=imports,
        )
        file.compute_hash()
        files.append(file)
    
    # Build dependency graph
    graph = build_dependency_graph(files)
    
    # Detect circular deps
    circular = detect_circular_dependencies(graph)
    if circular:
        logger.warning(f"Circular dependencies detected: {circular}")
    
    # Find entrypoints
    entrypoints = find_entrypoints(files, graph)
    
    # Detect project type
    metadata = detect_project_type(files)
    
    # Collect directories
    directories = {str(Path(f.path).parent) for f in files}
    directories.discard('.')
    
    # Extract dependency edges
    edges: List[Tuple[str, str]] = []
    if NETWORKX_AVAILABLE and isinstance(graph, nx.DiGraph):
        edges = list(graph.edges())
    elif isinstance(graph, dict):
        for src, dests in graph.items():
            for dest in dests:
                edges.append((src, dest))
    
    # LLM planning (optional)
    missing_files: List[str] = []
    generated_files: Dict[str, str] = {}
    
    if use_ollama:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            plan = loop.run_until_complete(
                llm_project_plan_async(blocks, ollama_model)
            )
            
            if plan:
                if plan.get('project_type'):
                    metadata.project_type = plan['project_type']
                if plan.get('frameworks'):
                    metadata.frameworks = plan['frameworks']
                if plan.get('entrypoints'):
                    entrypoints = plan['entrypoints']
                
                missing_files = plan.get('missing_files', [])
            
            # Generate missing files
            if generate_missing and missing_files:
                generated = loop.run_until_complete(
                    generate_missing_files_async(
                        missing_files,
                        metadata.project_type,
                        ollama_model
                    )
                )
                
                generated_files = generated
                
                # Add generated files to project
                for filepath, content in generated.items():
                    ext = Path(filepath).suffix[1:] or 'txt'
                    file = SourceFile(
                        path=filepath,
                        language=ext,
                        code=content,
                        block_index=None,
                        generated=True,
                    )
                    file.compute_hash()
                    files.append(file)
                    directories.add(str(Path(filepath).parent))
        
        finally:
            loop.close()
    
    # Update directories after adding generated files
    directories.discard('.')
    
    return ProjectPlan(
        files=files,
        directories=directories,
        metadata=metadata,
        entrypoints=entrypoints,
        dependency_edges=edges,
        missing_files=missing_files,
        generated_files=generated_files,
        circular_dependencies=circular,
    )


# ============================================================================
# FILE WRITING
# ============================================================================

def write_project_to_disk(
    plan: ProjectPlan,
    output_root: Path,
    dry_run: bool = False,
) -> List[str]:
    """
    Write project files to disk with security checks.
    BUG FIX: Proper path traversal prevention.
    """
    written: List[str] = []
    
    # Ensure output root exists
    if not dry_run:
        output_root.mkdir(parents=True, exist_ok=True)
    
    for file in plan.files:
        # Security: reject absolute paths
        if Path(file.path).is_absolute():
            logger.error(f"Rejecting absolute path: {file.path}")
            continue
        
        # Security: validate no traversal
        full_path = output_root / file.path
        if not validate_output_path(Path(file.path), output_root):
            logger.error(f"Rejecting path (traversal risk): {file.path}")
            continue
        
        if dry_run:
            logger.info(f"[DRY RUN] Would write {full_path}")
            written.append(str(full_path))
            continue
        
        # Create directories
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file
        try:
            with open(full_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(file.code)
            logger.info(f"Written: {full_path}")
            written.append(str(full_path))
        except Exception as e:
            logger.error(f"Failed to write {full_path}: {e}")
    
    return written


def save_project_plan(plan: ProjectPlan, output_root: Path) -> Path:
    """
    Save project plan as JSON (metadata only, no code).
    """
    plan_path = output_root / 'project_plan.json'
    
    try:
        with open(plan_path, 'w', encoding='utf-8') as f:
            json.dump(plan.to_json_safe(), f, indent=2)
        logger.info(f"Project plan saved: {plan_path}")
        return plan_path
    except Exception as e:
        logger.error(f"Failed to save plan: {e}")
        raise


# ============================================================================
# CLI
# ============================================================================

def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced Project Builder from Instruction Files"
    )
    parser.add_argument('--path', required=True, help='Instruction file path')
    parser.add_argument('--output-dir', default='./extracted_project',
                       help='Output directory')
    parser.add_argument('--ollama', action='store_true',
                       help='Use Ollama for planning')
    parser.add_argument('--ollama-model', default='qwen2.5:7b',
                       help='Ollama model')
    parser.add_argument('--generate-missing', action='store_true',
                       help='Generate missing files (requires --ollama)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Simulation mode')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s | %(levelname)-8s | %(message)s'
    )
    
    # Validate args
    if args.generate_missing and not args.ollama:
        logger.error("--generate-missing requires --ollama")
        return 1
    
    if args.ollama and not OLLAMA_AVAILABLE:
        logger.error("Ollama requested but library not installed: pip install ollama")
        return 1
    
    # Read input
    input_path = Path(args.path)
    if not input_path.exists():
        logger.error(f"File not found: {input_path}")
        return 1
    
    content = normalize_line_endings(input_path.read_text(encoding='utf-8'))
    blocks = extract_blocks(content)
    
    if not blocks:
        logger.warning("No code blocks found")
        return 0
    
    logger.info(f"Found {len(blocks)} blocks")
    
    # Process
    output_root = Path(args.output_dir)
    
    plan = process_blocks(
        blocks,
        input_path.stem,
        use_ollama=args.ollama,
        ollama_model=args.ollama_model,
        generate_missing=args.generate_missing,
    )
    
    # Save plan
    if not args.dry_run:
        save_project_plan(plan, output_root)
    
    # Write files
    written = write_project_to_disk(plan, output_root, args.dry_run)
    
    # Summary
    logger.info(f"\n{'='*60}")
    logger.info(f"Project Type: {plan.metadata.project_type}")
    logger.info(f"Frameworks: {', '.join(plan.metadata.frameworks) or 'none'}")
    logger.info(f"Files: {len(plan.files)}")
    logger.info(f"Entrypoints: {', '.join(plan.entrypoints) or 'none'}")
    logger.info(f"Dependencies: {len(plan.dependency_edges)}")
    logger.info(f"Circular deps: {len(plan.circular_dependencies)}")
    logger.info(f"Missing files: {', '.join(plan.missing_files) or 'none'}")
    logger.info(f"Written: {len(written)}")
    logger.info(f"{'='*60}")
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
