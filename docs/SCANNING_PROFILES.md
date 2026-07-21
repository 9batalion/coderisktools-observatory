# Scanner resource profiles

The local runner selects a scanner resource profile before scanning a repository. The profile is recorded in the CLI JSON summary as `scan_profile`.

## Profiles

| Profile | Tree limit | Scanner timeout | Max scanner output |
|---|---:|---:|---:|
| `small` | up to 10,000 files and 250 MiB | 120 s | 5 MiB |
| `medium` | up to 100,000 files and 2 GiB | 600 s | 20 MiB |
| `large` | up to 500,000 files and 10 GiB | 1,800 s | 50 MiB |
| `huge` | up to 2,000,000 files and 50 GiB | 3,600 s | 100 MiB |

`auto` is the default. It chooses the smallest profile whose file-count and byte limits contain the acquired tree. Explicit profiles are available for controlled operations:

```text
observatory scan ... --scan-profile auto
observatory scan ... --scan-profile large
```

A profile changes only local resource limits. It does not execute target code, enable network access inside the worker, or change the scanner ruleset digest.

## Fail-closed behavior

- scanner timeout becomes `scan_status=failed` with `scanner_timeout` in the structured error list;
- scanner output over the profile limit becomes `scan_status=failed` with `scanner_output_limit`;
- scanner exit codes outside 0/1 become a structured failed scan;
- failed scans generate a local report bundle and policy `HOLD`, not a false clean result;
- unexpected version/query/JSON errors remain hard adapter errors and are reported with `--verbose`.

The default profile remains bounded and conservative. Raising a profile is not evidence of a successful scan; the resulting bundle must still pass verification and policy review.
