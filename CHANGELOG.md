# Changelog

## V0.1.1 — 2026-10-21

- Added an explicit choice between TCP connect (`-sT`) and TCP SYN (`-sS`) scanning for Fast, Standard, and Detailed Service profiles. TCP connect remains the initial selection.
- Included the selected TCP method in terminal summaries, TXT/CSV reports, and saved snapshots.
- Allowed TCP connect and SYN snapshots to be compared within the same subnet and scan profile, with a note when methods differ.
- Preserved comparison support for older snapshots, which used TCP connect without a method label.
- Returned to the main menu after port-scan command failures and added SYN privilege guidance without silently changing methods.
- Updated usage and scan comparison documentation.

Validation: mocked checks covered both methods, all six scan branches, export/display behavior, cancellation, error handling, and snapshot comparisons. Live scans were also tested successfully before release.
