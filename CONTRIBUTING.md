# Contributing to Docker Image Migration Tool

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

- Be respectful and inclusive
- Assume good intent
- Focus on ideas, not individuals
- Help others learn and grow

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use a clear, descriptive title**
3. **Provide a minimal reproducible example** with:
   - Your Python version (`python --version`)
   - Docker version (`docker --version`)
   - Operating system
   - Steps to reproduce the issue
   - Expected vs actual behavior
4. **Include relevant logs** or error messages

### Suggesting Features

1. **Check existing issues** for similar requests
2. **Use a clear, descriptive title**
3. **Provide a detailed use case** explaining why the feature would be useful
4. **Include examples** of how you'd use it
5. **Be open to discussion** about the best approach

### Code Changes

#### Setup Development Environment

```bash
# Clone your fork
git clone https://github.com/yourusername/move-images.git
cd move-images

# Create a feature branch
git checkout -b feature/your-feature-name

# Install development dependencies
pip install pyyaml pytest
```

#### Development Workflow

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the [Code Style Guide](#code-style-guide)

3. **Add tests** for your changes:
   - Add test cases to `test_move_images.py`
   - Ensure all tests pass: `python -m pytest test_move_images.py -v`

4. **Update documentation** if needed:
   - Update README.md for user-facing changes
   - Update AGENTS.md for development information
   - Add comments for complex logic

5. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add feature description

   - Detailed explanation of changes
   - Why this change is needed
   - Any breaking changes or important notes"
   ```

6. **Push and create a Pull Request**:
   ```bash
   git push origin feature/your-feature-name
   ```

#### Pull Request Process

1. **Use a descriptive PR title** following this format:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation
   - `test:` for tests
   - `refactor:` for code refactoring
   - `chore:` for maintenance

2. **Include a description** explaining:
   - What the change does
   - Why it's needed
   - How to test it
   - Any breaking changes

3. **Link related issues** using GitHub's issue linking syntax:
   ```markdown
   Closes #123
   ```

4. **Ensure all tests pass** before submitting

5. **Keep commits clean** - rebase if needed to avoid merge commits

## Code Style Guide

### Python Style

- Follow [PEP 8](https://pep8.org/) conventions
- Use 4-space indentation (never tabs)
- Maximum line length: ~100 characters
- Use type hints on all function signatures

### Naming Conventions

- **Modules**: `snake_case` (e.g., `move_images.py`)
- **Classes**: `PascalCase` (e.g., `Spinner`)
- **Functions**: `snake_case` (e.g., `push_images`)
- **Variables**: `snake_case` (e.g., `image_name`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TIMEOUT`)

### Code Organization

```python
#!/usr/bin/env python3
"""Module docstring explaining the purpose."""

# Standard library imports (sorted alphabetically)
import argparse
import json
import pathlib

# Third-party imports (sorted alphabetically)
import yaml

# Constants
DEFAULT_TIMEOUT = 600
DISK_CHECK_MB = 1000

# Classes
class Spinner:
    """Class docstring."""
    pass

# Functions (organized logically)
def function_one():
    """Function docstring."""
    pass

def function_two():
    """Function docstring."""
    pass

# Main execution
if __name__ == "__main__":
    main()
```

### Docstrings

Use clear, concise docstrings:

```python
def push_images(images: List[Dict], registry_url: str) -> Dict:
    """Push Docker images to a registry.
    
    Args:
        images: List of image information dictionaries
        registry_url: URL of the target Docker registry
        
    Returns:
        Dictionary with push statistics (pushed, failed, skipped)
        
    Raises:
        RuntimeError: If registry is not accessible
    """
```

### Comments

- Use comments to explain **why**, not **what**
- Avoid obvious comments
- Use Spanish for internal logic comments (consistent with codebase)
- Keep comments up-to-date when code changes

### Error Handling

```python
# Good: Specific exceptions with helpful messages
try:
    result = subprocess.run(['docker', 'info'], check=True)
except subprocess.CalledProcessError as e:
    logging.error(f"Docker not available: {e}")
    return False

# Avoid: Generic exceptions
try:
    ...
except:
    pass
```

## Testing

### Adding Tests

1. **Add test cases** to `test_move_images.py`
2. **Follow the existing pattern**:
   ```python
   class TestFeatureName:
       """Test description."""
       
       def test_specific_behavior(self):
           """Test a specific behavior."""
           # Arrange
           input_data = ...
           
           # Act
           result = function_under_test(input_data)
           
           # Assert
           assert result == expected_value
   ```

3. **Use descriptive test names** that explain what's being tested

### Running Tests

```bash
# Run all tests
python -m pytest test_move_images.py -v

# Run specific test class
python -m pytest test_move_images.py::TestImageHasRegistry -v

# Run with coverage
python -m pytest test_move_images.py --cov=move_images
```

### Test Requirements

- **All new code must have tests**
- **All tests must pass** before submitting PR
- **Tests should cover** both normal and edge cases
- **No decrease in test coverage** without justification

## Documentation

### README.md

Update for:
- New user-facing features
- New command-line arguments
- New usage examples
- Changes to requirements or installation

### AGENTS.md

Update for:
- Internal function changes
- New helper functions
- Testing updates
- Build/test command changes

### Code Comments

Add comments for:
- Complex algorithms
- Non-obvious decisions
- Important implementation details
- Edge cases being handled

## Release Process

1. **Update version** in relevant files
2. **Update CHANGELOG** with new features/fixes
3. **Create a release tag**:
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```
4. **Create GitHub Release** with changelog

## Getting Help

- **Questions about contributing**: Open a discussion
- **Issues with tests**: Check test output and existing issues
- **Code review feedback**: Respond respectfully and iterate
- **General questions**: Open an issue with the `question` label

## Recognition

Contributors will be recognized in:
- Commit history
- GitHub contributors page
- Release notes
- README acknowledgments (for major contributions)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to make this tool better!** 🙏
