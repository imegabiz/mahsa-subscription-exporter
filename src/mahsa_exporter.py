import argparse
import ast
import base64
import binascii
import hashlib
import http.client
import json
import logging
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

REFERENCE_URL = (
    "https://raw.githubusercontent.com/MostafaDadkhah/"
    "MahsaNG-Desktop-Bridge/main/mahsa_bridge.py"
)
SUBSCRIPTION_URL = (
    "https://raw.githubusercontent.com/mahsanet/"
    "MahsaFreeConfig/refs/heads/main/app/sub.txt"
)

USER_AGENT = "mahsa-subscription-exporter/1.0"
REQUEST_TIMEOUT_SECONDS = 20
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 2.0
MAX_REFERENCE_BYTES = 2 * 1024 * 1024
MAX_SUBSCRIPTION_BYTES = 8 * 1024 * 1024

GROUPS = ("mtn", "mci")
LINK_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]{0,31})://([^\s#?/].*)$")
NON_CONFIG_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "sftp",
        "file",
        "data",
        "javascript",
        "ws",
        "wss",
        "blob",
        "about",
    }
)
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "configs.txt"

CANONICAL_FUNCTIONS = {
    "md5_hex": (
        "def md5_hex(text):\n"
        "    return hashlib.md5(text.encode('utf-8')).hexdigest().zfill(32)\n",
        "def md5_hex(text):\n"
        "    return hashlib.md5(text.encode('utf-8')).hexdigest()\n",
    ),
    "free_key": (
        "def free_key():\n"
        "    digest = md5_hex(FREE_KEY_SEED)\n"
        "    return digest[0:7] + digest[10:19]\n",
    ),
    "aes_cbc_decrypt_base64": (
        "def aes_cbc_decrypt_base64(ciphertext_b64, key, iv):\n"
        "    raw = base64.b64decode(''.join(ciphertext_b64.split()))\n"
        "    decryptor = Cipher(algorithms.AES(key.encode('utf-8')), "
        "modes.CBC(iv.encode('utf-8'))).decryptor()\n"
        "    padded = decryptor.update(raw) + decryptor.finalize()\n"
        "    unpadder = padding.PKCS7(128).unpadder()\n"
        "    plain = unpadder.update(padded) + unpadder.finalize()\n"
        "    return plain.decode('utf-8')\n",
    ),
}

REQUIRED_IMPORTS = (
    ("", "hashlib"),
    ("", "base64"),
    ("cryptography.hazmat.primitives", "padding"),
    ("cryptography.hazmat.primitives.ciphers", "Cipher"),
    ("cryptography.hazmat.primitives.ciphers", "algorithms"),
    ("cryptography.hazmat.primitives.ciphers", "modes"),
)

logger = logging.getLogger("mahsa_exporter")


class ExportError(Exception):
    pass


@dataclass(frozen=True)
class DecryptionParams:
    seed: str = field(repr=False)
    iv: str = field(repr=False)


@dataclass(frozen=True)
class Extraction:
    links: tuple
    records: dict
    valid: dict

    @property
    def unique(self):
        return len(self.links)


@dataclass(frozen=True)
class RunReport:
    records: dict
    valid: dict
    unique: int
    changed: bool
    duration_seconds: float


class _StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise ExportError("Redirect to a non-HTTPS URL was rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener():
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _StrictRedirectHandler(),
    )


def fetch_bytes(
    url,
    max_bytes,
    opener_factory=build_opener,
    sleep=time.sleep,
    attempts=MAX_ATTEMPTS,
):
    if urllib.parse.urlsplit(url).scheme.lower() != "https":
        raise ExportError("Only HTTPS URLs are allowed")
    last_failure = "unknown"
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "text/plain, */*"},
            )
            with opener_factory().open(
                request, timeout=REQUEST_TIMEOUT_SECONDS
            ) as response:
                status = getattr(response, "status", 200)
                if status != 200:
                    raise ExportError(f"Unexpected HTTP status {status}")
                data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ExportError("Response exceeds the size limit")
            if not data.strip():
                raise ExportError("Response is empty")
            return data
        except ExportError:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code in (408, 425, 429) or exc.code >= 500:
                last_failure = f"HTTP {exc.code}"
            else:
                raise ExportError(f"HTTP error {exc.code}") from None
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            ssl.SSLError,
            TimeoutError,
            ConnectionError,
            OSError,
        ) as exc:
            last_failure = type(exc).__name__
        if attempt < attempts:
            logger.warning(
                "Transient network failure (%s), retrying (%d/%d)",
                last_failure,
                attempt,
                attempts - 1,
            )
            sleep(BACKOFF_SECONDS * attempt)
    raise ExportError(
        f"Network failure after {attempts} attempts ({last_failure})"
    )


def parse_reference(source):
    try:
        return ast.parse(source.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError, ValueError, RecursionError, MemoryError):
        raise ExportError("Reference code could not be parsed") from None


def _top_level_string_constant(tree, name):
    values = []
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            values.append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
            and node.value is not None
        ):
            values.append(node.value)
    if len(values) != 1:
        raise ExportError(f"{name} could not be extracted from the reference code")
    value = values[0]
    if not (
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value
    ):
        raise ExportError(f"{name} is not a plain string constant")
    return value.value


def extract_params(tree):
    return DecryptionParams(
        seed=_top_level_string_constant(tree, "FREE_KEY_SEED"),
        iv=_top_level_string_constant(tree, "FREE_IV"),
    )


class _Normalizer(ast.NodeTransformer):
    def visit_arg(self, node):
        node.annotation = None
        node.type_comment = None
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.returns = None
        node.type_comment = None
        if (
            len(node.body) > 1
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            node.body = node.body[1:]
        return node


def _fingerprint(function_node):
    module = ast.Module(body=[function_node], type_ignores=[])
    module = _Normalizer().visit(module)
    return ast.dump(module, include_attributes=False)


def _canonical_fingerprints(name):
    fingerprints = set()
    for source in CANONICAL_FUNCTIONS[name]:
        function_node = ast.parse(source).body[0]
        fingerprints.add(_fingerprint(function_node))
    return fingerprints


def _find_function(tree, name):
    found = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(found) != 1 or not isinstance(found[0], ast.FunctionDef):
        raise ExportError(f"Function {name} is missing or ambiguous in the reference code")
    return found[0]


def _is_name(node, identifier):
    return isinstance(node, ast.Name) and node.id == identifier


def _is_call_to(node, identifier):
    return isinstance(node, ast.Call) and _is_name(node.func, identifier)


def _validate_imports(tree):
    present = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname in (None, alias.name):
                    present.add(("", alias.name))
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for alias in node.names:
                if alias.asname in (None, alias.name):
                    present.add((node.module or "", alias.name))
    for required in REQUIRED_IMPORTS:
        if required not in present:
            raise ExportError("Reference imports no longer match the known algorithm")


def _validate_decode_free(function_node):
    decrypt_call = None
    plain_name = None
    for node in ast.walk(function_node):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and _is_call_to(node.value, "aes_cbc_decrypt_base64")
        ):
            call = node.value
            if (
                len(call.args) == 3
                and not call.keywords
                and isinstance(call.args[0], ast.Name)
                and _is_call_to(call.args[1], "free_key")
                and not call.args[1].args
                and not call.args[1].keywords
                and _is_name(call.args[2], "FREE_IV")
            ):
                decrypt_call = call
                plain_name = node.targets[0].id
    if decrypt_call is None:
        raise ExportError("decode_free no longer matches the known decryption flow")
    encrypted_name = decrypt_call.args[0].id
    source_ok = any(
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _is_name(node.targets[0], encrypted_name)
        and any(_is_name(inner, "FREE_URL") for inner in ast.walk(node.value))
        for node in ast.walk(function_node)
    )
    if not source_ok:
        raise ExportError("decode_free no longer reads the known subscription source")
    parsed_ok = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "loads"
        and _is_name(node.func.value, "json")
        and len(node.args) == 1
        and _is_name(node.args[0], plain_name)
        for node in ast.walk(function_node)
    )
    if not parsed_ok:
        raise ExportError("decode_free no longer parses the decrypted JSON")


def validate_algorithm(tree):
    _validate_imports(tree)
    for name in CANONICAL_FUNCTIONS:
        function_node = _find_function(tree, name)
        if _fingerprint(function_node) not in _canonical_fingerprints(name):
            raise ExportError(f"Function {name} differs from the known algorithm")
    _validate_decode_free(_find_function(tree, "decode_free"))


def derive_key(seed):
    digest = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return digest[0:7] + digest[10:19]


def decrypt_subscription(payload, key, iv):
    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    if len(key_bytes) != 16:
        raise ExportError("Derived key has an unexpected length")
    if len(iv_bytes) != 16:
        raise ExportError("IV has an unexpected length")
    try:
        compact = "".join(payload.decode("ascii").split())
        raw = base64.b64decode(compact, validate=True)
    except (UnicodeDecodeError, binascii.Error, ValueError):
        raise ExportError("Subscription is not valid Base64") from None
    if not raw or len(raw) % 16 != 0:
        raise ExportError("Ciphertext length is not a multiple of the AES block size")
    try:
        decryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes)).decryptor()
        padded = decryptor.update(raw) + decryptor.finalize()
    except ValueError:
        raise ExportError("AES decryption failed") from None
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise ExportError("Invalid PKCS7 padding (parameters may have changed)") from None
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        raise ExportError("Decrypted data is not valid UTF-8") from None


def parse_payload(text):
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise ExportError("Decrypted data is not valid JSON") from None
    if not isinstance(data, dict):
        raise ExportError("Unexpected JSON structure: top level is not an object")
    return data


def _is_valid_link(link):
    if not link or len(link.splitlines()) != 1:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in link):
        return False
    match = LINK_PATTERN.match(link)
    if match is None:
        return False
    return match.group(1).lower() not in NON_CONFIG_SCHEMES


def extract_configs(data):
    records = {}
    valid = {}
    ordered = []
    for group in GROUPS:
        entries = data.get(group)
        if not isinstance(entries, list):
            raise ExportError(f"Unexpected JSON structure: group {group} is missing")
        records[group] = len(entries)
        valid[group] = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            candidate = entry.get("config")
            if not isinstance(candidate, str):
                continue
            link = candidate.strip()
            if not _is_valid_link(link):
                continue
            valid[group] += 1
            ordered.append(link)
    unique = tuple(dict.fromkeys(ordered))
    if not unique:
        raise ExportError("No valid configs were extracted")
    return Extraction(links=unique, records=records, valid=valid)


def _validate_output(data, expected_links):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ExportError("Output validation failed") from None
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise ExportError("Output validation failed")
    lines = text[:-1].split("\n")
    if tuple(lines) != tuple(expected_links) or len(set(lines)) != len(lines):
        raise ExportError("Output validation failed")
    if not all(_is_valid_link(line) for line in lines):
        raise ExportError("Output validation failed")


def write_output(path, links):
    path = Path(path)
    data = ("\n".join(links) + "\n").encode("utf-8")
    _validate_output(data, links)
    try:
        if path.exists() and path.read_bytes() == data:
            return False
    except OSError:
        raise ExportError("Existing output file could not be read") from None
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            delete=False,
            dir=path.parent,
            prefix=".configs-",
            suffix=".tmp",
        ) as handle:
            temp_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    except OSError:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        raise ExportError("Output file could not be written") from None
    return True


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write_step_summary(lines):
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    try:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        logger.warning("Step summary could not be written")


def run(output_path=DEFAULT_OUTPUT):
    started = time.monotonic()
    reference = fetch_bytes(REFERENCE_URL, MAX_REFERENCE_BYTES)
    logger.info("Reference code fetched")
    tree = parse_reference(reference)
    params = extract_params(tree)
    validate_algorithm(tree)
    logger.info("Decryption parameters extracted and algorithm validated")
    key = derive_key(params.seed)
    subscription = fetch_bytes(SUBSCRIPTION_URL, MAX_SUBSCRIPTION_BYTES)
    logger.info("Subscription fetched")
    plain = decrypt_subscription(subscription, key, params.iv)
    extraction = extract_configs(parse_payload(plain))
    logger.info(
        "Extracted %d unique configs (mtn records: %d, mci records: %d)",
        extraction.unique,
        extraction.records["mtn"],
        extraction.records["mci"],
    )
    changed = write_output(output_path, extraction.links)
    logger.info("Output file %s", "updated" if changed else "unchanged")
    return RunReport(
        records=extraction.records,
        valid=extraction.valid,
        unique=extraction.unique,
        changed=changed,
        duration_seconds=time.monotonic() - started,
    )


def _success_summary(report):
    return [
        "## Mahsa subscription export",
        "",
        "| Item | Value |",
        "| --- | --- |",
        "| Status | Success |",
        f"| Finished at | {_timestamp()} |",
        f"| Duration | {report.duration_seconds:.1f}s |",
        f"| mtn records / valid | {report.records['mtn']} / {report.valid['mtn']} |",
        f"| mci records / valid | {report.records['mci']} / {report.valid['mci']} |",
        f"| Unique configs | {report.unique} |",
        f"| configs.txt | {'changed' if report.changed else 'unchanged'} |",
    ]


def _failure_summary(reason):
    return [
        "## Mahsa subscription export",
        "",
        "| Item | Value |",
        "| --- | --- |",
        "| Status | Failed |",
        f"| Finished at | {_timestamp()} |",
        f"| Reason | {reason} |",
        "| configs.txt | previous version kept |",
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m src.mahsa_exporter",
        description="Export raw config links from the public MahsaFreeConfig subscription.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path of the output text file (default: configs.txt in the repository root).",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        report = run(args.output)
    except ExportError as exc:
        logger.error("Export failed: %s", exc)
        write_step_summary(_failure_summary(str(exc)))
        return 1
    except Exception as exc:
        reason = f"Unexpected error ({type(exc).__name__})"
        logger.error("Export failed: %s", reason)
        write_step_summary(_failure_summary(reason))
        return 1
    write_step_summary(_success_summary(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())