# Contributing to phantom-scan

> **Nyoul Labs** — Offensive Security Research & Development

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/nyuol-labs/phantom-scan.git`
3. Create a virtual environment: `python3 -m venv .venv`
4. Activate it: `source .venv/bin/activate`
5. Install in development mode: `pip install -e .`
6. Install dev dependencies: `pip install pytest black mypy`
7. Run tests: `python -m pytest tests/ -v`

## Adding a Module

1. Create your module in `src/modules/`
2. Add imports to `src/modules/__init__.py`
3. Add tests in `tests/`
4. Ensure all tests pass: `python -m pytest tests/ -v`
5. Format code: `black src/ tests/`
6. Type check: `mypy src/`

## Code Style

- Line length: 100 characters
- Use type hints everywhere
- Docstrings for all public functions
- Logging instead of print statements
- Follow the existing module structure

## Commit Convention

- `feat:` new feature
- `fix:` bug fix  
- `refactor:` code changes without behavior changes
- `test:` adding or updating tests
- `docs:` documentation changes

## Pull Request Process

1. Ensure CI passes
2. Update documentation if needed
3. Add tests for any new functionality
4. Keep changes focused and small

## About Nyoul Labs

Nyoul Labs is a specialized offensive security research lab focused on
advanced network exploitation, penetration testing, and security tooling development.
