# Verdict and Support Classification

Original verdict values are retained and mapped case-insensitively to malicious, suspicious, benign, unknown, or failed. A failed result code/status overrides an otherwise unknown verdict.

For each run, consider VTI observations with score at least 3. Classify a VTI from stable category/operation/classification metadata: AV when normalized metadata tokens contain `antivirus` or `av`; YARA when they contain `yara`; otherwise behavioral. Description text is not used.

- `av_only`: at least one AV, no YARA, no behavioral.
- `yara_only`: at least one YARA, no AV, no behavioral.
- `av_and_yara_only`: both AV and YARA, no behavioral.
- `av_or_yara_only`: any AV/YARA, no behavioral (the union of the preceding three).
- `behavioral`: at least one non-AV/non-YARA high-confidence VTI.
- `none`: no high-confidence VTI.

These flags describe support evidence, not a replacement verdict.
