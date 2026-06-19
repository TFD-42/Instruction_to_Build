import argparse
import asyncio
import hashlib
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Callable
from collections import defaultdict
from enum import Enum
from urllib.parse import quote
import subprocess
from datetime import datetime
 
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
 
try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None
 
# ============================================================================
# CONSTANTS
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
 
DEFAULT_CONFIG = {
    'max_file_size_mb': 10,
    'max_project_files': 5000,
    'parallel_workers': 4,
    'llm_max_retries': 3,
    'llm_timeout_seconds': 30,
    'enable_mermaid': True,
    'enable_tree': True,
    'enable_sbom': True,
    'enable_html_report': True,
}
 
logger = logging.getLogger(__name__)
 
# ============================================================================
# DATACLASSES (Enhanced)
# ============================================================================
 
@dataclass(slots=True)
class ImportInfo:
    """Represents a single import/dependency in source code."""
    module: str
    is_relative: bool
    raw: str
    resolved_path: Optional[str] = None
    language: Optional[str] = None
 
    def to_dict(self) -> Dict[str, Any]:
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
    size_bytes: int = 0
    encoding: str = 'utf-8'
 
    def compute_hash(self) -> str:
        """Compute SHA256 of code."""
        self.hash_sha256 = hashlib.sha256(
            self.code.encode(self.encoding)
        ).hexdigest()
        self.size_bytes = len(self.code.encode(self.encoding))
        return self.hash_sha256
 
    def to_dict_metadata_only(self) -> Dict[str, Any]:
        """Serialize without code (for project_plan.json)."""
        return {
            'path': self.path,
            'language': self.language,
            'block_index': self.block_index,
            'generated': self.generated,
            'hash_sha256': self.hash_sha256,
            'size_bytes': self.size_bytes,
            'imports': [asdict(imp) for imp in self.imports],
        }
 
 
@dataclass(slots=True)
class ProjectMetadata:
    """Project type and framework detection."""
    project_type: str
    frameworks: List[str] = field(default_factory=list)
    has_config_files: List[str] = field(default_factory=list)
    language_stats: Dict[str, int] = field(default_factory=dict)
 
    def to_dict(self) -> Dict[str, Any]:
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
    statistics: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
 
    def to_json_safe(self) -> Dict[str, Any]:
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
            'statistics': self.statistics,
            'created_at': self.created_at,
        }
 
 
# ============================================================================
# REGEX PATTERNS (Fixed)
# ============================================================================
 
PATH_PATTERNS: List[re.Pattern] = [
    re.compile(r'^(?:#|//|--)\s*(?P<path>[\w\-/.]+\.[a-zA-Z0-9]+)\s*$', re.MULTILINE),
    re.compile(r'^/\*\s*(?P<path>[\w\-/.]+\.[a-zA-Z0-9]+)\s*\*/$', re.MULTILINE),
]
 
BLOCK_RE: re.Pattern = re.compile(r'```([^\n]*)\n(.*?)\n```', re.DOTALL)
 
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
    """Security check: ensure path doesn't escape output_root."""
    try:
        resolved = (output_root / path).resolve()
        root_resolved = output_root.resolve()
        return root_resolved in resolved.parents or resolved == root_resolved
    except (ValueError, RuntimeError):
        return False
 
 
def normalize_relative_import(module: str, lang: str) -> str:
    """
    BUG FIX #3: Normalize JS relative paths.
    ./Button -> Button (for graph matching)
    """
    if lang == 'js':
        # Remove ./ and ../ for comparison
        module = re.sub(r'^\./', '', module)
        module = re.sub(r'^\.\./', '', module)
    return module
 
 
def safe_path_check(path: str) -> bool:
    """
    BUG FIX #6: Early check for traversal in generated files.
    """
    parts = Path(path).parts
    return '..' not in parts and not Path(path).is_absolute()
 
 
# ============================================================================
# BLOCK EXTRACTION
# ============================================================================
 
def extract_blocks(content: str) -> List[Tuple[str, str, Optional[str], int]]:
    """Extract code blocks from markdown."""
    blocks: List[Tuple[str, str, Optional[str], int]] = []
    
    for idx, match in enumerate(BLOCK_RE.finditer(content), start=1):
        info_line = match.group(1).strip()
        code = match.group(2)
        
        parts = info_line.split(maxsplit=1)
        language = parts[0].lower() if parts else 'txt'
        explicit_path = None
        
        if len(parts) > 1:
            remainder = parts[1]
            title_match = re.search(r'title=["\']([^"\']+)["\']', remainder)
            if title_match:
                explicit_path = title_match.group(1)
            else:
                explicit_path = remainder.strip('"\'')
        
        blocks.append((language, code, explicit_path, idx))
    
    return blocks
 
 
# ============================================================================
# PATH DETECTION
# ============================================================================
 
def detect_explicit_path_in_code(code: str) -> Optional[str]:
    """Extract explicit path from comment in first 10 lines."""
    lines = code.split('\n')[:10]
    
    for line in lines:
        stripped = line.lstrip()
        
        for pattern in PATH_PATTERNS:
            match = pattern.search(stripped)
            if match:
                candidate = match.group('path')
                candidate = candidate.replace('\\', '/')
                return candidate
    
    return None
 
 
# ============================================================================
# IMPORT DETECTION & RESOLUTION (Enhanced & Fixed)
# ============================================================================
 
class ImportResolver:
    """
    ENHANCEMENT #6: Plugin system for language-specific import resolution.
    """
    def __init__(self):
        self.cache: Dict[Tuple[str, str, str], Optional[str]] = {}
        self.resolvers: Dict[str, Callable] = {
            'py': self._resolve_python,
            'js': self._resolve_javascript,
            'go': self._resolve_golang,
            'rs': self._resolve_rust,
            'java': self._resolve_java,
            'c': self._resolve_c,
            'cpp': self._resolve_cpp,
        }
    
    def resolve(self, module: str, lang: str) -> Optional[str]:
        """ENHANCEMENT #7: Caching for import resolution."""
        cache_key = (module, lang, 'resolve')
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        resolver = self.resolvers.get(lang, lambda m: None)
        result = resolver(module)
        self.cache[cache_key] = result
        return result
    
    def _resolve_python(self, module: str) -> Optional[str]:
        """Python: api.routes -> api/routes.py"""
        if not module:
            return None
        
        # Remove leading dots
        depth = 0
        while module.startswith('.'):
            depth += 1
            module = module[1:]
        
        if not module:
            return None
        
        path = module.replace('.', '/')
        return path + '.py'
    
    def _resolve_javascript(self, module: str) -> Optional[str]:
        """JavaScript: ./Button -> Button.js, normalize path."""
        if not module:
            return None
        
        # BUG FIX #3: Normalize relative paths
        module = normalize_relative_import(module, 'js')
        
        if module.startswith('./') or module.startswith('../'):
            return module + '.js'
        elif not any(c in module for c in './@'):
            # External package
            return None
        
        return module + '.js'
    
    def _resolve_golang(self, module: str) -> Optional[str]:
        """Go: github.com/pkg/name -> name.go"""
        if not module:
            return None
        parts = module.split('/')
        return (parts[-1] + '.go') if parts else None
    
    def _resolve_rust(self, module: str) -> Optional[str]:
        """Rust: crate::db::models -> crate/db/models.rs"""
        if not module:
            return None
        path = module.replace('::', '/')
        return path + '.rs'
    
    def _resolve_java(self, module: str) -> Optional[str]:
        """Java: com.example.App -> com/example/App.java"""
        if not module:
            return None
        path = module.replace('.', '/')
        return path + '.java'
    
    def _resolve_c(self, module: str) -> Optional[str]:
        """C: stdlib.h -> stdlib.h"""
        if not module:
            return None
        # BUG FIX #2: Handle system headers properly
        if module.endswith(('.h', '.c')):
            return module
        return None
    
    def _resolve_cpp(self, module: str) -> Optional[str]:
        """C++: iostream -> iostream.hpp"""
        if not module:
            return None
        # BUG FIX #2: Simplified logic
        if module.endswith(('.h', '.hpp', '.cpp')):
            return module
        return module + '.hpp'
    
    def clear_cache(self) -> None:
        """ENHANCEMENT #7: Cache management."""
        self.cache.clear()
 
 
# Global resolver instance
RESOLVER = ImportResolver()
 
 
def detect_imports(code: str, lang: str) -> List[ImportInfo]:
    """Detect imports/dependencies with deduplication."""
    if lang not in IMPORT_PATTERNS:
        return []
    
    imports: List[ImportInfo] = []
    seen: Set[str] = set()
    
    if lang == 'go':
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
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        module = m.group(1)
                        if module not in seen:
                            seen.add(module)
                            imports.append(ImportInfo(
                                module=module,
                                is_relative=False,
                                raw=line,
                                language=lang,
                            ))
    
    for pattern, is_relative in IMPORT_PATTERNS[lang]:
        for match in pattern.finditer(code):
            module = match.group(1)
            
            if module in seen:
                continue
            
            seen.add(module)
            imports.append(ImportInfo(
                module=module,
                is_relative=is_relative,
                raw=match.group(0),
                language=lang,
            ))
    
    return imports
 
 
# ============================================================================
# PROJECT TYPE DETECTION (Enhanced)
# ============================================================================
 
def detect_project_type(files: List[SourceFile]) -> ProjectMetadata:
    """Enhanced project type detection with language stats."""
    file_paths = {f.path for f in files}
    
    project_type = 'unknown'
    frameworks: List[str] = []
    config_files: List[str] = []
    language_stats: Dict[str, int] = defaultdict(int)
    
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
    
    for file in files:
        language_stats[file.language] += 1
        
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
    
    if 'Dockerfile' in file_paths:
        frameworks.append('docker')
    
    return ProjectMetadata(
        project_type=project_type,
        frameworks=list(set(frameworks)),
        has_config_files=config_files,
        language_stats=dict(language_stats),
    )
 
 
# ============================================================================
# DEPENDENCY GRAPH (Enhanced)
# ============================================================================
 
def build_dependency_graph(files: List[SourceFile]) -> Union[nx.DiGraph, Dict[str, List[str]]]:
    """Build dependency graph with improved path matching."""
    if NETWORKX_AVAILABLE:
        G = nx.DiGraph()
        
        for file in files:
            G.add_node(file.path)
        
        for file in files:
            for imp in file.imports:
                if imp.resolved_path:
                    for target_file in files:
                        if (imp.resolved_path in target_file.path or 
                            target_file.path.endswith(imp.resolved_path) or
                            target_file.path.endswith('/' + imp.resolved_path)):
                            G.add_edge(file.path, target_file.path)
                            break
        
        return G
    else:
        deps: Dict[str, List[str]] = defaultdict(list)
        for file in files:
            for imp in file.imports:
                if imp.resolved_path:
                    deps[file.path].append(imp.resolved_path)
        return dict(deps)
 
 
def detect_circular_dependencies(graph: Union[nx.DiGraph, Dict]) -> List[List[str]]:
    """Detect circular dependencies."""
    if not NETWORKX_AVAILABLE or not isinstance(graph, nx.DiGraph):
        return []
    
    try:
        cycles = list(nx.simple_cycles(graph))
        return cycles
    except Exception as e:
        logger.error(f"Circular dependency detection failed: {e}")
        return []
 
 
def find_entrypoints(files: List[SourceFile], graph: Union[nx.DiGraph, Dict]) -> List[str]:
    """Find entrypoint files with better heuristics."""
    entrypoints: List[str] = []
    
    if NETWORKX_AVAILABLE and isinstance(graph, nx.DiGraph):
        roots = [n for n in graph.nodes if graph.in_degree(n) == 0]
        if roots:
            entrypoints = roots
    
    if not entrypoints:
        for file in files:
            basename = Path(file.path).stem.lower()
            for hint in ENTRYPOINT_HEURISTICS:
                if hint in basename:
                    entrypoints.append(file.path)
                    break
    
    if not entrypoints:
        py_files = [f.path for f in files if f.language == 'py']
        entrypoints = py_files[:1] if py_files else [files[0].path if files else None]
    
    return [e for e in entrypoints if e]
 
 
# ============================================================================
# LLM INTEGRATION (Fixed & Enhanced)
# ============================================================================
 
async def llm_project_plan_async(
    blocks: List[Tuple[str, str, Optional[str], int]],
    model: str,
    max_retries: int = 3,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    BUG FIX #1: Use asyncio.to_thread for proper async blocking calls.
    ENHANCEMENT #14: Retry logic with exponential backoff.
    ENHANCEMENT #15: Batch planning.
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
    
    for attempt in range(max_retries):
        try:
            # BUG FIX #1: Use asyncio.to_thread for blocking ollama.chat()
            def call_ollama():
                return ollama.chat(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                )
            
            response = await asyncio.wait_for(
                asyncio.to_thread(call_ollama),
                timeout=timeout
            )
            
            raw = response['message']['content'].strip()
            json_match = re.search(r'\{.*\}', raw, re.DOTALL)
            if json_match:
                raw = json_match.group(0)
            
            plan = json.loads(raw)
            logger.info(f"LLM planning succeeded: {plan.get('project_type')}")
            return plan
        
        except asyncio.TimeoutError:
            logger.warning(f"LLM call timeout (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
        except Exception as e:
            logger.warning(f"LLM call failed (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
    
    return {}
 
 
async def generate_missing_files_async(
    missing_files: List[str],
    project_type: str,
    model: str,
    max_retries: int = 3,
) -> Dict[str, str]:
    """Generate missing files with retry logic."""
    if not OLLAMA_AVAILABLE or not missing_files:
        return {}
    
    # BUG FIX #6: Early safety check on filenames
    safe_files = [f for f in missing_files if safe_path_check(f)]
    if not safe_files:
        logger.error("No safe file paths in missing_files")
        return {}
    
    prompt = f"""
You are a developer. Generate content for missing files in a {project_type} project.
 
Missing files: {', '.join(safe_files)}
 
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
    
    for attempt in range(max_retries):
        try:
            def call_ollama():
                return ollama.chat(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                )
            
            response = await asyncio.to_thread(call_ollama)
            content = response['message']['content']
            blocks = extract_blocks(content)
            
            generated: Dict[str, str] = {}
            for lang, code, explicit_path, idx in blocks:
                if explicit_path and safe_path_check(explicit_path):
                    generated[explicit_path] = code
                elif not explicit_path:
                    fallback = f"missing_{idx}.{lang}"
                    if safe_path_check(fallback):
                        generated[fallback] = code
            
            logger.info(f"Generated {len(generated)} missing files")
            return generated
        
        except Exception as e:
            logger.warning(f"File generation failed (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
    
    return {}
 
 
# ============================================================================
# EXPORT FORMATS (Enhancements)
# ============================================================================
 
def export_mermaid_graph(plan: ProjectPlan) -> str:
    """ENHANCEMENT #3: Export dependency graph as Mermaid diagram."""
    lines = ['graph TD']
    
    for src, dst in plan.dependency_edges:
        src_quoted = quote(src, safe='')
        dst_quoted = quote(dst, safe='')
        lines.append(f'    {src_quoted}["{src}"]')
        lines.append(f'    {dst_quoted}["{dst}"]')
        lines.append(f'    {src_quoted} --> {dst_quoted}')
    
    return '\n'.join(lines)
 
 
def export_tree_format(plan: ProjectPlan) -> str:
    """ENHANCEMENT #4: Export project structure as tree."""
    def build_tree(path: str, prefix: str = '', is_last: bool = True) -> List[str]:
        current_prefix = '└── ' if is_last else '├── '
        result = [prefix + current_prefix + path.split('/')[-1]]
        
        children = [f for f in plan.files if f.path.startswith(path + '/')]
        for i, child in enumerate(children):
            is_last_child = (i == len(children) - 1)
            next_prefix = prefix + ('    ' if is_last else '│   ')
            result.extend(build_tree(child.path, next_prefix, is_last_child))
        
        return result
    
    tree_lines = ['project/']
    for directory in sorted(plan.directories):
        tree_lines.extend(build_tree(directory))
    
    return '\n'.join(tree_lines)
 
 
def generate_html_report(plan: ProjectPlan, output_path: Path) -> Path:
    """ENHANCEMENT #8: Generate HTML report."""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Project Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .stat {{ background: #f5f5f5; padding: 10px; margin: 10px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        code {{ background: #f4f4f4; padding: 2px 5px; }}
    </style>
</head>
<body>
    <h1>Project Analysis Report</h1>
    <p>Generated: {plan.created_at}</p>
    
    <h2>Project Metadata</h2>
    <div class="stat">
        <strong>Type:</strong> {plan.metadata.project_type}<br>
        <strong>Frameworks:</strong> {', '.join(plan.metadata.frameworks) or 'None'}<br>
        <strong>Config Files:</strong> {', '.join(plan.metadata.has_config_files) or 'None'}
    </div>
    
    <h2>Statistics</h2>
    <div class="stat">
        <strong>Total Files:</strong> {len(plan.files)}<br>
        <strong>Total Directories:</strong> {len(plan.directories)}<br>
        <strong>Dependencies:</strong> {len(plan.dependency_edges)}<br>
        <strong>Entrypoints:</strong> {', '.join(plan.entrypoints) or 'None'}
    </div>
    
    <h2>File Listing</h2>
    <table>
        <tr><th>Path</th><th>Language</th><th>Size</th><th>Hash</th></tr>
        {''.join(f'<tr><td>{f.path}</td><td>{f.language}</td><td>{f.size_bytes}</td><td><code>{f.hash_sha256[:8]}</code></td></tr>'
            for f in plan.files)}
    </table>
    
    <h2>Circular Dependencies</h2>
    <div class="stat">
        {f"Found {len(plan.circular_dependencies)} cycles" if plan.circular_dependencies else "No cycles detected"}
    </div>
</body>
</html>
"""
    
    report_path = output_path / 'report.html'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path
 
 
def generate_sbom(plan: ProjectPlan) -> Dict[str, Any]:
    """
    ENHANCEMENT #21: SBOM (Software Bill of Materials) generation.
    Minimal SPDX-like structure.
    """
    return {
        'spdxVersion': 'SPDX-2.3',
        'creationInfo': {
            'created': plan.created_at,
            'creators': ['Tool: ProjectBuilder'],
        },
        'packages': [
            {
                'SPDXID': f"SPDXRef-File{i}",
                'name': f.path,
                'downloadLocation': 'NOASSERTION',
                'filesAnalyzed': False,
                'checksums': [
                    {
                        'algorithm': 'SHA256',
                        'checksumValue': f.hash_sha256,
                    }
                ],
            }
            for i, f in enumerate(plan.files)
        ],
    }
 
 
# ============================================================================
# PARALLEL PROCESSING (Enhancement)
# ============================================================================
 
def process_blocks_parallel(
    blocks: List[Tuple[str, str, Optional[str], int]],
    base_name: str,
    max_workers: int = 4,
) -> List[SourceFile]:
    """ENHANCEMENT #1: Parallel block processing."""
    files: List[SourceFile] = []
    
    def process_block(block_tuple: Tuple[str, str, Optional[str], int]) -> SourceFile:
        lang, code, explicit_path, idx = block_tuple
        
        if explicit_path:
            path = explicit_path
        else:
            detected = detect_explicit_path_in_code(code)
            if detected:
                path = detected
            else:
                ext = get_extension(lang)
                path = f"{base_name}_{idx}.{ext}"
        
        path = path.replace('\\', '/')
        imports = detect_imports(code, lang)
        
        for imp in imports:
            imp.resolved_path = RESOLVER.resolve(imp.module, lang)
        
        file = SourceFile(
            path=path,
            language=lang,
            code=code,
            block_index=idx,
            imports=imports,
        )
        file.compute_hash()
        
        # BUG FIX #5: Check file size limits
        if file.size_bytes > DEFAULT_CONFIG['max_file_size_mb'] * 1024 * 1024:
            logger.warning(f"File {path} exceeds size limit, truncating")
            file.code = file.code[:100000]
            file.compute_hash()
        
        return file
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        files = list(executor.map(process_block, blocks))
    
    return files
 
 
# ============================================================================
# MAIN PIPELINE (Enhanced)
# ============================================================================
 
def process_blocks(
    blocks: List[Tuple[str, str, Optional[str], int]],
    base_name: str,
    use_ollama: bool = False,
    ollama_model: str = 'qwen2.5:7b',
    generate_missing: bool = False,
    parallel: bool = True,
    config: Optional[Dict[str, Any]] = None,
) -> ProjectPlan:
    """Process code blocks with all enhancements."""
    if config is None:
        config = DEFAULT_CONFIG
    
    # BUG FIX #5: Duplicate detection
    seen_paths: Set[str] = set()
    unique_blocks = []
    for block in blocks:
        lang, code, path, idx = block
        if path and path in seen_paths:
            logger.warning(f"Duplicate path {path}, skipping")
            continue
        if path:
            seen_paths.add(path)
        unique_blocks.append(block)
    
    blocks = unique_blocks
    
    # Process blocks
    if parallel:
        files = process_blocks_parallel(blocks, base_name, config['parallel_workers'])
    else:
        files = process_blocks_parallel(blocks, base_name, max_workers=1)
    
    # Build graph
    graph = build_dependency_graph(files)
    circular = detect_circular_dependencies(graph)
    if circular:
        logger.warning(f"Circular dependencies: {circular}")
    
    # Find entrypoints
    entrypoints = find_entrypoints(files, graph)
    
    # Detect project type
    metadata = detect_project_type(files)
    
    # Directories
    directories = {str(Path(f.path).parent) for f in files}
    if '.' in directories:
        directories.discard('.')
    
    # Dependency edges
    edges: List[Tuple[str, str]] = []
    if NETWORKX_AVAILABLE and isinstance(graph, nx.DiGraph):
        edges = list(graph.edges())
    
    # Statistics
    statistics = {
        'total_files': len(files),
        'total_size_bytes': sum(f.size_bytes for f in files),
        'unique_imports': len(set(imp.module for f in files for imp in f.imports)),
        'dependency_edges': len(edges),
        'circular_dependencies': len(circular),
    }
    
    # LLM planning (if enabled)
    missing_files: List[str] = []
    generated_files: Dict[str, str] = {}
    
    if use_ollama:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            plan = loop.run_until_complete(
                llm_project_plan_async(
                    blocks,
                    ollama_model,
                    max_retries=config['llm_max_retries'],
                    timeout=config['llm_timeout_seconds'],
                )
            )
            
            if plan:
                if plan.get('project_type'):
                    metadata.project_type = plan['project_type']
                if plan.get('frameworks'):
                    metadata.frameworks = plan['frameworks']
                if plan.get('entrypoints'):
                    entrypoints = plan['entrypoints']
                
                missing_files = plan.get('missing_files', [])
            
            if generate_missing and missing_files:
                generated = loop.run_until_complete(
                    generate_missing_files_async(
                        missing_files,
                        metadata.project_type,
                        ollama_model,
                        max_retries=config['llm_max_retries'],
                    )
                )
                
                generated_files = generated
                
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
                    parent = Path(filepath).parent
                    if parent != Path('.'):
                        directories.add(str(parent))
        
        finally:
            loop.close()
    
    return ProjectPlan(
        files=files,
        directories=directories,
        metadata=metadata,
        entrypoints=entrypoints,
        dependency_edges=edges,
        missing_files=missing_files,
        generated_files=generated_files,
        circular_dependencies=circular,
        statistics=statistics,
    )
 
 
# ============================================================================
# FILE WRITING (Enhanced)
# ============================================================================
 
def write_project_to_disk(
    plan: ProjectPlan,
    output_root: Path,
    dry_run: bool = False,
    parallel: bool = True,
) -> List[str]:
    """Write project files with concurrent writing."""
    written: List[str] = []
    
    if not dry_run:
        output_root.mkdir(parents=True, exist_ok=True)
    
    def write_file(file: SourceFile) -> Optional[str]:
        if Path(file.path).is_absolute():
            logger.error(f"Rejecting absolute path: {file.path}")
            return None
        
        if not validate_output_path(Path(file.path), output_root):
            logger.error(f"Rejecting path (traversal): {file.path}")
            return None
        
        full_path = output_root / file.path
        
        if dry_run:
            logger.info(f"[DRY RUN] Would write {full_path}")
            return str(full_path)
        
        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with open(full_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write(file.code)
            logger.info(f"Written: {full_path}")
            return str(full_path)
        except Exception as e:
            logger.error(f"Write failed {full_path}: {e}")
            return None
    
    if parallel:
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(write_file, plan.files)
            written = [r for r in results if r]
    else:
        written = [r for r in (write_file(f) for f in plan.files) if r]
    
    return written
 
 
def save_project_plan(plan: ProjectPlan, output_root: Path) -> Path:
    """Save plan as JSON."""
    plan_path = output_root / 'project_plan.json'
    
    try:
        with open(plan_path, 'w', encoding='utf-8') as f:
            json.dump(plan.to_json_safe(), f, indent=2)
        logger.info(f"Plan saved: {plan_path}")
        return plan_path
    except Exception as e:
        logger.error(f"Plan save failed: {e}")
        raise
 
 
# ============================================================================
# CLI
# ============================================================================
 
def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Advanced Project Builder - Enhanced Edition"
    )
    parser.add_argument('--path', required=True, help='Instruction file')
    parser.add_argument('--output-dir', default='./extracted_project', help='Output dir')
    parser.add_argument('--ollama', action='store_true', help='Use Ollama')
    parser.add_argument('--ollama-model', default='qwen2.5:7b', help='Ollama model')
    parser.add_argument('--generate-missing', action='store_true', help='Generate missing files')
    parser.add_argument('--dry-run', action='store_true', help='Simulation mode')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--parallel', action='store_true', default=True, help='Parallel processing')
    parser.add_argument('--no-parallel', dest='parallel', action='store_false', help='Disable parallelism')
    parser.add_argument('--export-mermaid', action='store_true', help='Export Mermaid graph')
    parser.add_argument('--export-tree', action='store_true', help='Export tree format')
    parser.add_argument('--html-report', action='store_true', default=True, help='Generate HTML report')
    
    args = parser.parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s | %(levelname)-8s | %(message)s'
    )
    
    if args.generate_missing and not args.ollama:
        logger.error("--generate-missing requires --ollama")
        return 1
    
    if args.ollama and not OLLAMA_AVAILABLE:
        logger.error("Ollama not available: pip install ollama")
        return 1
    
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
    
    output_root = Path(args.output_dir)
    
    plan = process_blocks(
        blocks,
        input_path.stem,
        use_ollama=args.ollama,
        ollama_model=args.ollama_model,
        generate_missing=args.generate_missing,
        parallel=args.parallel,
    )
    
    if not args.dry_run:
        save_project_plan(plan, output_root)
        
        if args.export_mermaid:
            mermaid = export_mermaid_graph(plan)
            (output_root / 'graph.mmd').write_text(mermaid)
            logger.info("Exported: graph.mmd")
        
        if args.export_tree:
            tree = export_tree_format(plan)
            (output_root / 'tree.txt').write_text(tree)
            logger.info("Exported: tree.txt")
        
        if args.html_report:
            generate_html_report(plan, output_root)
            logger.info("Exported: report.html")
        
        sbom = generate_sbom(plan)
        (output_root / 'sbom.json').write_text(json.dumps(sbom, indent=2))
        logger.info("Exported: sbom.json")
    
    written = write_project_to_disk(plan, output_root, args.dry_run, args.parallel)
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Type: {plan.metadata.project_type}")
    logger.info(f"Frameworks: {', '.join(plan.metadata.frameworks) or 'none'}")
    logger.info(f"Files: {len(plan.files)} | Size: {plan.statistics['total_size_bytes']} bytes")
    logger.info(f"Entrypoints: {', '.join(plan.entrypoints)}")
    logger.info(f"Dependencies: {len(plan.dependency_edges)}")
    logger.info(f"Circular deps: {len(plan.circular_dependencies)}")
    logger.info(f"Written: {len(written)}")
    logger.info(f"{'='*60}")
    
    return 0
 
 
if __name__ == '__main__':
    import sys
    sys.exit(main())
