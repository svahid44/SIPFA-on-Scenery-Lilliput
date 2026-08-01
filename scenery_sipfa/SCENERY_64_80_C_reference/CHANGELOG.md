# Changelog

## 1.0.0 — 2026-07-31

- Validated the SCENERY-64/80 C implementation against official vectors, a complete round trace, Python cross-validation, and structural tests.
- Added a persistent single-entry logical S-box fault model.
- Implemented detection-based and infection-based dataset generators.
- Completed Scenario 1: known fault + detection, including full `SK28` recovery and repeated experiments.
- Completed Scenario 2: unknown fault + detection, including fault localization, exhaustive active-key filtering, unique `delta`, and the honest 18/20-bit consensus result.
- Completed Scenario 3: known fault + infection, including full `SK28` recovery and repeated experiments.
- Completed Scenario 4: unknown fault + infection, including SEI localization, exact `2^20` active-key ranking, structural-equivalence proof, and repeated experiments.
- Added CSV datasets, publication figures, Excel analysis workbooks, and Persian technical reports.
- Added GitHub Actions CI, citation metadata, reproducibility instructions, and upload guidance.
