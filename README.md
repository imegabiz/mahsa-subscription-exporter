# mahsa-subscription-exporter

A small, standalone Python tool that downloads the public encrypted MahsaFreeConfig subscription, decrypts it, and saves the raw config links to a plain text file, `configs.txt`. A GitHub Actions workflow does this automatically every hour.

> **Unofficial project.** This repository is independent and unofficial. It is not affiliated with, endorsed by, or approved by MahsaNet or the authors of the referenced projects.

## What it does

Every run performs these steps:

1. Downloads the public reference code (`mahsa_bridge.py`) over HTTPS.
2. Parses it with `ast.parse()` and reads the current `FREE_KEY_SEED` and `FREE_IV` constants. The reference code is never executed, imported, or evaluated.
3. Verifies that the key derivation and decryption logic still match the known algorithm.
4. Derives the AES key from the seed.
5. Downloads the encrypted subscription.
6. Decrypts it and parses the JSON.
7. Extracts the `config` field of every valid record in the `mtn` group, then the `mci` group.
8. Removes duplicates, keeping the order of first appearance.
9. Writes `configs.txt` atomically, only after every check has passed.

The project has no dependency on Multi or any other project.

## Public sources

| Purpose | URL |
| --- | --- |
| Reference code (parameters and algorithm) | https://raw.githubusercontent.com/MostafaDadkhah/MahsaNG-Desktop-Bridge/main/mahsa_bridge.py |
| Encrypted subscription | https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/app/sub.txt |

## Decryption overview

- Key: take the lowercase hex MD5 digest of the seed (UTF-8). The key is `digest[0:7] + digest[10:19]`, a 16-character string used as its UTF-8 bytes (not as hex).
- Cipher: Base64 decoding, then AES-128-CBC with a 16-byte IV, then PKCS7 unpadding (128-bit block), then UTF-8 decoding, then JSON parsing.
- Only the Seed and IV are read dynamically. If they change, the tool follows automatically.
- The functions `md5_hex`, `free_key`, `aes_cbc_decrypt_base64` and `decode_free` of the reference code are compared structurally (normalized AST, so whitespace, comments, docstrings and type hints do not matter). If the logic has really changed, the run stops. The tool never guesses a new algorithm and never executes downloaded code.

## Repository layout

```
.github/workflows/update-subscription.yml   hourly workflow
src/__init__.py
src/mahsa_exporter.py                       all logic and CLI
tests/test_mahsa_exporter.py                offline unit tests
configs.txt                                 output (one link per line)
requirements.txt                            runtime dependency (cryptography)
requirements-dev.txt                        test dependencies
.gitignore
LICENSE
README.md
```

## Output format

`configs.txt` lives in the repository root. It contains one raw link per line (`vless://`, `vmess://`, `trojan://` or `ss://`) and nothing else: no header, footer, timestamp, comments, or diagnostics. Links are stored exactly as received (only surrounding whitespace is trimmed). Records with other schemes, empty values, or non-string values are skipped.

Once the repository is public, the raw file can be consumed at:

```
https://raw.githubusercontent.com/<your-user>/mahsa-subscription-exporter/main/configs.txt
```

Replace `<your-user>` with the account that owns the repository, and `main` with the default branch if it differs.

## Manual run

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m src.mahsa_exporter
```

To write to another file: `python -m src.mahsa_exporter --output /path/to/file.txt`

The exit code is `0` on success and `1` on failure.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

All tests run offline with mocked HTTP; they never contact the real sources.

## GitHub Actions workflow

`.github/workflows/update-subscription.yml` runs:

- every hour at minute 17 (`17 * * * *`, UTC),
- manually via **Actions → Update subscription → Run workflow**.

Steps: checkout, set up Python, install dependencies, run tests, run the exporter, then commit and push `configs.txt` only if it actually changed. The workflow uses the standard `GITHUB_TOKEN` with `contents: write`; no personal access token or extra secret is needed. Make sure **Settings → Actions → General → Workflow permissions** allows workflows to write to the repository if your organization restricts it, and that pushes to the default branch are not blocked by branch protection for `github-actions[bot]`.

The job summary shows only non-sensitive information: status, finish time (UTC), per-group record counts, number of unique configs, whether `configs.txt` changed, and a general failure reason.

Scheduling limits: GitHub does not guarantee execution at the exact minute; scheduled runs can be delayed or occasionally skipped under load. GitHub also disables scheduled workflows in a public repository after 60 days without repository activity, so check the Actions tab occasionally.

## Failure behavior

If any step fails (sources unreachable, reference code unparsable, Seed/IV missing, algorithm changed, invalid Base64/AES/padding/UTF-8/JSON, unexpected JSON structure, no valid config, or a write/validation error), the run fails visibly in Actions and the previous `configs.txt` is left untouched. Transient network errors are retried a limited number of times. If the algorithm itself changes, the code needs a manual update.

## Security and privacy

- HTTPS only, with certificate verification, request timeouts, response size limits, and rejection of HTTPS-to-HTTP redirects.
- The Seed, IV, derived key, subscription content, and links are never logged or written to the job summary, and are not stored in the repository.
- Writes are atomic (temporary file, then replace).
- **Public repository note:** if this repository is public, everything in `configs.txt` is publicly visible and downloadable by anyone.

## License and attribution

The code in this repository is released under the [MIT License](LICENSE). The MIT License covers only this project's own code. It does not grant any rights to third-party content. The extracted links come from a third-party source (MahsaFreeConfig); this project makes no claim of ownership over them, and their use is subject to the terms set by their respective owners. The reference code is from the MahsaNG-Desktop-Bridge project by its respective author, and is used only to read public parameters; none of its code is copied here.
