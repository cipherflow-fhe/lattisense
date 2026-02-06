# Contributing to LattiSense

Thank you for your interest in contributing to LattiSense! This document provides guidelines and instructions for contributing.

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub:

1. Search existing issues to avoid duplicates
2. Use a clear and descriptive title
3. Provide as much context as possible:
   - Your operating system and version
   - Compiler version (GCC/Clang)
   - CMake version
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - Error messages or logs

### Submitting Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the coding standards below
3. **Test your changes** by building and running the test suite
4. **Submit a pull request** with a clear description of your changes

### Development Workflow

```bash
# Clone your fork
git clone https://github.com/<your-username>/lattisense.git
cd lattisense

# Create a feature branch
git checkout -b feature/your-feature-name

# Build with tests enabled
mkdir build && cd build
cmake .. -DLATTISENSE_BUILD_TESTS=ON
make -j$(nproc)

# Run tests
cd ../unittests
python3 test_cpu_bfv.py
python3 test_cpu_ckks.py
cd ../build/unittests
./test_lattigo
./test_cpu_bfv
./test_cpu_ckks
```

## Coding Standards

### C++ Style

- Use C++20 standard features
- Follow the existing code style in the repository
- Use clang-format with the provided `.clang-format` configuration:

```bash
# Format your code before committing
find . -name "*.cpp" -o -name "*.h" | xargs clang-format -i
```

### Python Style

- Use Python 3.10+ features
- Format code with ruff:

```bash
ruff format .
```

### Commit Messages

- Use clear and descriptive commit messages
- Start with a verb in imperative mood (e.g., "Add", "Fix", "Update")
- Keep the first line under 72 characters
- Reference issues when applicable (e.g., "Fixes #123")

Example:
```
Add BFV rotation support for CPU backend

- Implement left and right rotation operations
- Add unit tests for rotation functionality
- Update documentation with usage examples

Fixes #42
```

## Code Review Process

1. All pull requests require at least one review
2. CI checks must pass before merging
3. Address review feedback and update your PR as needed
4. Squash commits if requested

## License

By contributing to LattiSense, you agree that your contributions will be licensed under the Apache License 2.0.

## Questions?

If you have questions about contributing, feel free to open a discussion on GitHub.
