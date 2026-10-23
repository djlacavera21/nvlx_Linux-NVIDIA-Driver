# NVIDIA security comparison review — 2026-10-23

## Scope and decision

Advance the reviewed `NVIDIA/product-security` baseline from
`f99a1fd2ba74a3fe59e8a6cac3869f48cfb5d4b6` to
`2c9454053cf5d2942d4f361d455c749b725fe920` after completing the capped comparison.
The scanner itself never advances this configuration automatically.

The [upstream comparison](https://github.com/NVIDIA/product-security/compare/f99a1fd2ba74a3fe59e8a6cac3869f48cfb5d4b6...2c9454053cf5d2942d4f361d455c749b725fe920)
is ancestral and contains 11 commits. Its comparison API response lists 300 files.
Complete recursive trees identify 400 changed files, including 34 Markdown files.
Both tree responses are explicitly untruncated:

| Snapshot | Tree SHA | Entries |
| --- | --- | ---: |
| Previous baseline | `d3aeaba487759fa2b3306eaa37123b07b1015d15` | 2,574 |
| Reviewed head | `4f0a23c96fa5df60e8d5a7b9f1953d77ae898c5f` | 2,972 |

The live scanner inspected all 34 changed Markdown files and reported three
matching paths for the configured managed-component terms:

| Path | Status | Matched component |
| --- | --- | --- |
| `2026/5861/5861.md` | Added | GPU Display Driver |
| `2026/5861/README.md` | Added | GPU Display Driver |
| `2026/README.md` | Modified | GPU Display Driver |

These are three references to one bulletin, not three separate advisories.
The scan correctly returned status 2 until this review was recorded.

## Bulletin 5861 applicability

The pinned [GPU Display Driver bulletin](https://github.com/NVIDIA/product-security/blob/2c9454053cf5d2942d4f361d455c749b725fe920/2026/5861/5861.md)
was updated on 2026-10-13. Its Linux driver tables identify these fixed releases:

| Linux branch | Fixed release |
| --- | --- |
| R580 | `580.178.04` |
| R595 | `595.91.07` |
| R610 | `610.57.04` |
| R615 | `615.71.09` |

All 240 Linux R610 table rows, covering 80 CVE identifiers across GeForce,
RTX/Quadro/NVS, and Tesla, specify `610.57.04`. This exactly matches both
`config/driver-series.toml` and `nvlx.config.DEFAULT` in this release.
No change to the default driver pin is required by this bulletin's R610 rows.
Versions from different driver branches must not be compared as a single
global minimum. Custom configurations and installed fleet versions need their
own platform and branch assessment; the bulletin also has separate vGPU tables.

## Other changed bulletins

The changed numbered bulletin documents cover the following products. The
scanner applied the existing configured terms to all changed Markdown files;
the managed-component match above was the only matching bulletin. Review of
these titles does not certify unrelated applications or networking firmware.

| Bulletin | Product |
| --- | --- |
| 5847 | BlueField / ConnectX networking |
| 5861 | GPU Display Driver |
| 5867 | DGX Spark |
| 5868 | Megatron Bridge |
| 5875 | Triton Inference Server |
| 5879 | Infrastructure Controller |
| 5881 | Megatron LM |
| 5885 | NeMo Speech |
| 5886 | DeepStream |
| 5889 | AIStore |
| 5890 | NVSentinel |
| 5891 | TensorRT |
| 5900 | DALI |
| 5901 | Warp |
| 5902 | Isaac Lab |
| 5903 | Model-Optimizer |

## Monitor behavior

For comparisons at the 300-file cap, the monitor resolves immutable baseline
and head commits to complete recursive trees. It validates tree identity,
truncation flags, paths, object identities, and entry types before enumerating
the full delta. Renames become a removal and addition. Dedicated bulletins
retain full context; aggregate indexes are compared using reconstructed deltas.
Network failures, incomplete trees, malformed responses, and non-ancestral
baselines continue to stop verification.

References: [GitHub comparison limits](https://docs.github.com/en/rest/commits/commits#compare-two-commits)
and [GitHub recursive-tree limits](https://docs.github.com/en/rest/git/trees#get-a-tree).
