# AGENTS.md

## Build/Test/Lint Commands

### Running the Application
```bash
# Basic usage
python move_images.py --help

# Save images to disk
python move_images.py save --docker-compose docker-compose.yml --output-dir /path/to/images

# Push images to registry
python move_images.py push --docker-compose docker-compose.yml --registry-url registry.example.com

# Load images from disk
python move_images.py load --output-dir /path/to/images

# Pull images from registry
python move_images.py pull --registry-config registry_config.json
```

### Tests
A comprehensive test suite exists with 15 tests covering core functionality:
```bash
# Run all tests
python -m pytest test_move_images.py -v

# Run specific test class
python -m pytest test_move_images.py::TestImageHasRegistry -v

# Syntax check
python -m py_compile move_images.py

# CLI validation
python move_images.py --help
```

**Test Coverage:**
- `TestImageHasRegistry`: Registry detection in image names (3 tests)
- `TestGenerateSafeFilename`: Safe filename generation (4 tests)
- `TestGetMetadataPath`: Metadata path resolution (3 tests)
- `TestMetadata`: Metadata save/load and validation (3 tests)
- `TestDiskSpace`: Disk space verification (2 tests)

**Current Status:** ✅ All 15 tests passing

### Linting
No external linter configured. Follow PEP 8 conventions based on code patterns.

---

## Code Style Guidelines

### Imports
- Group standard library imports first, then third-party
- Use explicit imports (avoid `from module import *`)
- Order: `__future__`, standard library, third-party, local
- Example: `from typing import Optional, Dict, List, Tuple`

### Naming Conventions
- **Modules**: `snake_case` (e.g., `move_images.py`)
- **Classes**: `PascalCase` (e.g., `Spinner`)
- **Functions**: `snake_case` (e.g., `push_images`, `check_docker_available`)
- **Variables**: `snake_case` (e.g., `image_name`, `registry_url`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TIMEOUT`, `DISK_CHECK_MB`)

### Types
- Use type hints for function signatures
- Prefer `Optional[T]` for nullable values
- Use `List[Dict]`, `Tuple[Type, Type]` for collections
- Import from `typing`: `Optional`, `Dict`, `List`, `Tuple`

### Error Handling
- Use `try-except` blocks with specific exceptions
- Log errors with `logging.error()` or `logging.warning()`
- Raise `RuntimeError` for recoverable errors with context
- Return `bool` or `None` from functions to indicate success/failure
- Provide helpful error messages with actionable solutions

### Formatting
- indent using 4 spaces (no tabs)
- Line length: ~100 characters
- Use f-strings for string interpolation
- Place blank lines between top-level functions (2 lines for major sections)
- Add blank line after imports section
- Align continuation lines for long function calls

### Comments
- Use Spanish comments based on codebase patterns
- Document complex logic, avoid obvious comments
- Use emoji markers for UI feedback: ✅ ❌ ⏭️ 📦 🔐

### File Structure
- Single-file application (no modules)
- Major sections separated by `# ====================` comments
- Constants at module level
- Classes before functions
- Main execution block at end: `if __name__ == "__main__": main()`

### Docker/CLI Conventions
- Use pathlib for file operations
- Prefer `subprocess.run()` with `check=True` for shell commands
- Use `capture_output=True` to hide command noise
- Pass timeout to long-running subprocess operations
- Environment variables: `REGISTRY_USER`, `REGISTRY_PASSWORD`

### Security
- Always set `chmod 600` on credential files
- Use `--password-stdin` for docker login
- Prefer env vars over CLI args for secrets
- Validate inputs before subprocess calls

### Logging
- Initialize logging: `logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')`
- Use `logging.error()` for failures
- Use `logging.warning()` for recoverable issues
- Include actionable information in log messages

---

## Cursor/Copilot Rules

None configured.
