# Contributing to the DLP System

Thank you for contributing to the Data Leakage Prevention (DLP) system.

## Code of Conduct

Maintain professional, constructive, and respectful interactions across all project channels.

## Development Principles

1. **Security by Design:** Default to least privilege, deny-by-default access, robust input sanitization, and output encoding.
2. **Data Minimization & Redaction:** Sensitive findings must be masked immediately upon detection. Never persist or log unredacted sensitive payload fragments unless explicitly approved and segregated in secure evidence vaults.
3. **No Synthetic Secrets in Repositories:** Never commit production keys, live API credentials, or customer PII.
4. **Tested Changes:** Every detector, policy rule, authorization check, or API endpoint must be accompanied by comprehensive tests in `tests/`.

## Workflow

1. Fork or branch from `master` (`git checkout -b feature/your-feature-name`).
2. Set up the development environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   cp .env.example .env
   ```
3. Implement your changes following modular architecture guidelines.
4. Run quality checks locally:
   ```bash
   ruff check .
   bandit -r app
   pytest --cov=app tests/
   ```
5. Commit clean, atomic commits with clear messages.
6. Open a pull request with a detailed description of the changes and test results.
