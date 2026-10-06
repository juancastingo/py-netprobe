# Contributing to py-netprobe

Thank you for contributing to `py-netprobe`!

## Local Development

```bash
git clone https://github.com/juancastingo/py-netprobe.git
cd py-netprobe
pip install -e ".[dev]"
pytest
```

## Guidelines

- Keep the diagnostic engine free of mandatory third-party dependencies (100% standard library Python).
- Ensure accurate millisecond latency measurements at each socket stage.
- Preserve clear diagnostic error exceptions and root-cause explanations.
