# Paper artifacts

This directory is generated automatically from the actual experiment logs and CSV files.

## Figures

PDF files are vector graphics suitable for LaTeX.
PNG files are exported at 300 DPI for slides and quick previews.

## Tables

Each `.tex` file can be included directly with `\\input{...}`.

## Reproducibility

Re-run:

```bash
source .venv-paper/bin/activate
python scripts/generate_paper_artifacts.py --project-root .
```

The generator does not hard-code experimental results. Missing scenarios are skipped and marked as not verified.
