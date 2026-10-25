import base64
import hashlib
import json
import logging
import os
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src import mahsa_exporter as mx

ROOT = Path(__file__).resolve().parent.parent

CURRENT_SEED = "mvcfhjju5632gfsseu95642yhfhnhjhty68532gfg"
CURRENT_IV = "lvcas56410c97lpb"
CURRENT_KEY = "ca815ecfdb1f153a"

REFERENCE_TEMPLATE = '''
from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
from typing import Literal

try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise SystemExit("missing") from exc

FREE_URL = "https://example.invalid/sub.txt"
FREE_IV = "__IV__"       # note
EMS_IV = "Xvc1wOrxs77Ilj0N"
FREE_KEY_SEED = "__SEED__"
EMS_KEY_SEED = "aassddy734321thjmvbxcdgtt67i7kmghddfhfdxb"


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest().zfill(32)


def free_key() -> str:
    digest = md5_hex(FREE_KEY_SEED)
    return __SLICE__


def aes_cbc_decrypt_base64(ciphertext_b64: str, key: str, iv: str) -> str:
    raw = base64.b64decode("".join(ciphertext_b64.split()))
    decryptor = Cipher(algorithms.AES(key.encode("utf-8")), modes.__MODE__(iv.encode("utf-8"))).decryptor()
    padded = decryptor.update(raw) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return plain.decode("utf-8")


def decode_free(carrier="all", timeout=30):
    encrypted = fetch_text(FREE_URL, timeout=timeout).strip()
    plain = aes_cbc_decrypt_base64(encrypted, free_key(), FREE_IV)
    data = json.loads(plain)
    return data
'''


def make_reference(
    seed=CURRENT_SEED,
    iv=CURRENT_IV,
    key_slice="digest[0:7] + digest[10:19]",
    mode="CBC",
    decode_override=None,
):
    source = (
        REFERENCE_TEMPLATE.replace("__SEED__", seed)
        .replace("__IV__", iv)
        .replace("__SLICE__", key_slice)
        .replace("__MODE__", mode)
    )
    if decode_override is not None:
        head = source.split("def decode_free")[0]
        source = head + decode_override
    return source.encode("utf-8")


def derive(seed):
    digest = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return digest[0:7] + digest[10:19]


def encrypt(plain, seed=CURRENT_SEED, iv=CURRENT_IV):
    if not isinstance(plain, str):
        plain = json.dumps(plain)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(derive(seed).encode()), modes.CBC(iv.encode())
    ).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize())


def sample_payload():
    return {
        "mtn": [
            {"config": "vless://uuid-1@host1:443?type=ws#one", "hash": "h1", "ads_url": "a"},
            {"config": "vmess://eyJhZGQiOiJ4In0=", "hash": "h2"},
            {"hash": "no-config"},
        ],
        "mci": [
            {"config": "trojan://pass@host2:443#two"},
            {"config": "ss://YWVzOnBhc3M=@host3:8388#three"},
            {"config": "vless://uuid-1@host1:443?type=ws#one"},
        ],
    }


EXPECTED_LINKS = [
    "vless://uuid-1@host1:443?type=ws#one",
    "vmess://eyJhZGQiOiJ4In0=",
    "trojan://pass@host2:443#two",
    "ss://YWVzOnBhc3M=@host3:8388#three",
]


@pytest.fixture
def served(monkeypatch):
    state = {"reference": make_reference(), "subscription": encrypt(sample_payload())}

    def fake_fetch(url, max_bytes, *args, **kwargs):
        value = state["reference"] if url == mx.REFERENCE_URL else state["subscription"]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(mx, "fetch_bytes", fake_fetch)
    return state


class FakeResponse:
    def __init__(self, data, status=200):
        self.data = data
        self.status = status

    def read(self, amount=-1):
        return self.data if amount < 0 else self.data[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def open(self, request, timeout=None):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def fetch_with(outcomes, max_bytes=1000, attempts=3):
    opener = FakeOpener(outcomes)
    sleeps = []
    result = None
    error = None
    try:
        result = mx.fetch_bytes(
            "https://example.invalid/x",
            max_bytes,
            opener_factory=lambda: opener,
            sleep=sleeps.append,
            attempts=attempts,
        )
    except mx.ExportError as exc:
        error = exc
    return result, error, opener, sleeps


def test_extracts_seed_and_iv_from_reference():
    params = mx.extract_params(mx.parse_reference(make_reference()))
    assert params.seed == CURRENT_SEED
    assert params.iv == CURRENT_IV
    mx.validate_algorithm(mx.parse_reference(make_reference()))


def test_current_seed_produces_expected_key():
    assert mx.derive_key(CURRENT_SEED) == CURRENT_KEY


def test_new_seed_with_unchanged_algorithm(served, tmp_path):
    new_seed = "brand-new-seed-value-123"
    served["reference"] = make_reference(seed=new_seed)
    served["subscription"] = encrypt(sample_payload(), seed=new_seed)
    out = tmp_path / "configs.txt"
    report = mx.run(out)
    assert report.changed is True
    assert out.read_text().splitlines() == EXPECTED_LINKS


def test_new_iv_is_used(served, tmp_path):
    new_iv = "0123456789abcdef"
    served["reference"] = make_reference(iv=new_iv)
    served["subscription"] = encrypt(sample_payload(), iv=new_iv)
    out = tmp_path / "configs.txt"
    mx.run(out)
    assert out.read_text().splitlines() == EXPECTED_LINKS


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key_slice": "digest[0:8] + digest[10:18]"},
        {"key_slice": "digest[10:19] + digest[0:7]"},
        {"mode": "CFB"},
        {
            "decode_override": (
                "def decode_free(carrier='all', timeout=30):\n"
                "    encrypted = fetch_text(FREE_URL, timeout=timeout).strip()\n"
                "    plain = aes_cbc_decrypt_base64(encrypted, free_key(), EMS_IV)\n"
                "    return json.loads(plain)\n"
            )
        },
    ],
    ids=["slice-bounds", "slice-order", "cipher-mode", "decode-free-iv"],
)
def test_real_algorithm_change_stops_safely(served, tmp_path, kwargs):
    served["reference"] = make_reference(**kwargs)
    out = tmp_path / "configs.txt"
    out.write_text("vless://old@h:1#old\n")
    with pytest.raises(mx.ExportError):
        mx.run(out)
    assert out.read_text() == "vless://old@h:1#old\n"


def test_formatting_and_docstring_changes_are_tolerated():
    source = make_reference().decode().replace(
        "def free_key() -> str:",
        'def free_key()   ->   str:\n    """Docstring."""',
    ).replace("digest[0:7] + digest[10:19]", "digest[0:7]+digest[10:19]")
    mx.validate_algorithm(mx.parse_reference(source.encode()))


@pytest.mark.parametrize(
    "source",
    [
        b"def broken(:\n",
        b"\xff\xfe\x00bad",
        b"x = 1\n",
        make_reference().replace(b'FREE_KEY_SEED = "', b'FREE_KEY_SEED = str("').replace(b'gfg"\n', b'gfg")\n'),
        make_reference().replace(b"def free_key", b"def other_key"),
    ],
    ids=["syntax-error", "invalid-bytes", "no-constants", "non-constant-seed", "missing-function"],
)
def test_invalid_reference_is_rejected(source):
    with pytest.raises(mx.ExportError):
        tree = mx.parse_reference(source)
        mx.extract_params(tree)
        mx.validate_algorithm(tree)


def test_decrypt_success_and_padding_removed():
    for plain in ("x", "a" * 15, "b" * 16, "c" * 17, '{"k": "ü"}'):
        payload = encrypt(plain)
        assert mx.decrypt_subscription(payload, CURRENT_KEY, CURRENT_IV) == plain


def test_invalid_base64_is_rejected():
    for payload in (b"@@@not-base64@@@", b"abc", "ü".encode()):
        with pytest.raises(mx.ExportError):
            mx.decrypt_subscription(payload, CURRENT_KEY, CURRENT_IV)


def test_aes_and_padding_failures():
    good = encrypt("hello world")
    with pytest.raises(mx.ExportError):
        mx.decrypt_subscription(good, "0000000000000000", CURRENT_IV)
    truncated = base64.b64encode(base64.b64decode(good) + b"\x00" * 5)
    with pytest.raises(mx.ExportError):
        mx.decrypt_subscription(truncated, CURRENT_KEY, CURRENT_IV)
    with pytest.raises(mx.ExportError):
        mx.decrypt_subscription(good, "short", CURRENT_IV)
    with pytest.raises(mx.ExportError):
        mx.decrypt_subscription(good, CURRENT_KEY, "short")


def test_invalid_utf8_and_json():
    raw = b"\xff\xfe\xfd"
    padder = padding.PKCS7(128).padder()
    padded = padder.update(raw) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(CURRENT_KEY.encode()), modes.CBC(CURRENT_IV.encode())
    ).encryptor()
    payload = base64.b64encode(encryptor.update(padded) + encryptor.finalize())
    with pytest.raises(mx.ExportError):
        mx.decrypt_subscription(payload, CURRENT_KEY, CURRENT_IV)
    for text in ("not json", "[1, 2]", "", "null"):
        with pytest.raises(mx.ExportError):
            mx.parse_payload(text)


def test_extracts_links_from_both_groups_in_order():
    result = mx.extract_configs(sample_payload())
    assert list(result.links) == EXPECTED_LINKS
    assert result.records == {"mtn": 3, "mci": 3}
    assert result.valid == {"mtn": 2, "mci": 3}
    assert result.unique == 4


def test_duplicates_removed_keeping_first_occurrence():
    data = {
        "mtn": [{"config": "ss://b@h:1#b"}, {"config": "ss://a@h:1#a"}, {"config": "ss://b@h:1#b"}],
        "mci": [{"config": "ss://a@h:1#a"}, {"config": "ss://c@h:1#c"}],
    }
    assert list(mx.extract_configs(data).links) == [
        "ss://b@h:1#b",
        "ss://a@h:1#a",
        "ss://c@h:1#c",
    ]


def test_incomplete_records_and_invalid_configs_are_ignored():
    data = {
        "mtn": [
            "string-record",
            None,
            {},
            {"config": ""},
            {"config": "   "},
            {"config": 123},
            {"config": None},
            {"config": "http://example.com/x"},
            {"config": "vless://"},
            {"config": "vless://a@h:1\n#bad"},
            {"config": "  vless://ok@h:1#ok  "},
        ],
        "mci": [],
    }
    result = mx.extract_configs(data)
    assert list(result.links) == ["vless://ok@h:1#ok"]
    assert result.records == {"mtn": 11, "mci": 0}


@pytest.mark.parametrize(
    "data",
    [
        {"mtn": [], "mci": []},
        {"mtn": [{"config": "nope"}], "mci": [{"hash": "x"}]},
        {"mtn": []},
        {"mtn": {}, "mci": []},
        {"mci": [{"config": "ss://a@h:1"}]},
    ],
)
def test_no_valid_config_or_bad_structure_fails(data):
    with pytest.raises(mx.ExportError):
        mx.extract_configs(data)


def test_http_failure_leaves_output_untouched(served, tmp_path):
    out = tmp_path / "configs.txt"
    out.write_text("vless://old@h:1#old\n")
    served["subscription"] = mx.ExportError("Network failure after 3 attempts")
    with pytest.raises(mx.ExportError):
        mx.run(out)
    assert out.read_text() == "vless://old@h:1#old\n"
    served["reference"] = mx.ExportError("HTTP error 404")
    with pytest.raises(mx.ExportError):
        mx.run(out)
    assert out.read_text() == "vless://old@h:1#old\n"


def test_decryption_failure_leaves_output_untouched(served, tmp_path):
    out = tmp_path / "configs.txt"
    out.write_text("vless://old@h:1#old\n")
    served["subscription"] = encrypt(sample_payload(), seed="a-different-seed")
    with pytest.raises(mx.ExportError):
        mx.run(out)
    assert out.read_text() == "vless://old@h:1#old\n"


def test_structure_failure_leaves_output_untouched(served, tmp_path):
    out = tmp_path / "configs.txt"
    out.write_text("vless://old@h:1#old\n")
    served["subscription"] = encrypt({"mtn": [], "other": []})
    with pytest.raises(mx.ExportError):
        mx.run(out)
    served["subscription"] = encrypt({"mtn": [{"config": "bad"}], "mci": []})
    with pytest.raises(mx.ExportError):
        mx.run(out)
    assert out.read_text() == "vless://old@h:1#old\n"


def test_valid_output_file_format(served, tmp_path):
    out = tmp_path / "configs.txt"
    report = mx.run(out)
    assert out.read_bytes() == ("\n".join(EXPECTED_LINKS) + "\n").encode()
    assert report.unique == 4
    assert report.changed is True
    assert not list(tmp_path.glob(".configs-*"))


def test_previous_output_kept_when_write_fails(served, tmp_path, monkeypatch):
    out = tmp_path / "configs.txt"
    out.write_text("vless://old@h:1#old\n")

    def failing_replace(src, dst):
        raise OSError("disk failure")

    monkeypatch.setattr(mx.os, "replace", failing_replace)
    with pytest.raises(mx.ExportError):
        mx.run(out)
    assert out.read_text() == "vless://old@h:1#old\n"
    assert not list(tmp_path.glob(".configs-*"))


def test_identical_content_does_not_touch_file(served, tmp_path, monkeypatch):
    out = tmp_path / "configs.txt"
    mx.run(out)
    before = out.stat().st_mtime_ns
    calls = []
    monkeypatch.setattr(mx.os, "replace", lambda *a: calls.append(a))
    report = mx.run(out)
    assert report.changed is False
    assert calls == []
    assert out.stat().st_mtime_ns == before


def test_links_are_not_modified(served, tmp_path):
    tricky = [
        "vless://3f2b9c1e-0000-4000-8000-123456789abc@Host.Example.com:443?security=tls&sni=A.b&path=%2Fws%3Fed%3D2048#My%20Name%20%F0%9F%94%A5",
        "vmess://eyJ2IjoiMiIsInBzIjoi2KfYqiIsImFkZCI6IjEuMS4xLjEifQ==",
        "trojan://Pa55%2Bword@Example.com:8443?type=grpc#Raw name with spaces",
        "ss://YWVzLTEyOC1nY206U2VjcmV0QDEyMw==@1.2.3.4:8388#ShadowName",
    ]
    served["subscription"] = encrypt(
        {"mtn": [{"config": link, "hash": "x", "ads_url": "y"} for link in tricky], "mci": []}
    )
    out = tmp_path / "configs.txt"
    mx.run(out)
    assert out.read_text(encoding="utf-8").splitlines() == tricky


def test_no_secret_or_content_in_logs_or_summary(served, tmp_path, caplog, capsys, monkeypatch):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    caplog.set_level(logging.DEBUG)
    out = tmp_path / "configs.txt"
    assert mx.main(["--output", str(out)]) == 0
    served["subscription"] = encrypt("not json")
    assert mx.main(["--output", str(out)]) == 1
    captured = capsys.readouterr()
    everything = caplog.text + captured.out + captured.err + summary.read_text()
    forbidden = [CURRENT_SEED, CURRENT_IV, CURRENT_KEY, "uuid-1", "host1", "pass@host2", "YWVzOnBhc3M"]
    forbidden += [served["subscription"].decode()]
    for value in forbidden:
        assert value not in everything
    assert "Success" in summary.read_text()
    assert "Failed" in summary.read_text()


def test_module_runs_independently_of_github_actions():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
    result = subprocess.run(
        [sys.executable, "-m", "src.mahsa_exporter", "--help"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "--output" in result.stdout


def test_transient_errors_are_retried_then_succeed():
    result, error, opener, sleeps = fetch_with(
        [urllib.error.URLError("boom"), TimeoutError(), FakeResponse(b"data")]
    )
    assert error is None
    assert result == b"data"
    assert opener.calls == 3
    assert len(sleeps) == 2


def test_server_error_retried_and_exhaustion_fails():
    http_503 = urllib.error.HTTPError("https://x", 503, "err", {}, None)
    result, error, opener, sleeps = fetch_with([http_503, http_503, http_503])
    assert result is None
    assert isinstance(error, mx.ExportError)
    assert opener.calls == 3


def test_client_error_is_not_retried():
    http_404 = urllib.error.HTTPError("https://x", 404, "nf", {}, None)
    result, error, opener, sleeps = fetch_with([http_404, FakeResponse(b"data")])
    assert isinstance(error, mx.ExportError)
    assert opener.calls == 1
    assert sleeps == []


def test_empty_oversized_and_bad_status_responses_rejected():
    assert fetch_with([FakeResponse(b"  \n")])[1] is not None
    assert fetch_with([FakeResponse(b"x" * 2000)], max_bytes=1000)[1] is not None
    assert fetch_with([FakeResponse(b"data", status=204)])[1] is not None


def test_https_enforced_and_https_downgrade_redirect_rejected():
    with pytest.raises(mx.ExportError):
        mx.fetch_bytes("http://example.invalid/x", 1000)
    handler = mx._StrictRedirectHandler()
    request = mx.urllib.request.Request("https://example.invalid/x")
    with pytest.raises(mx.ExportError):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.invalid/y")
    redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://example.invalid/y")
    assert redirected.full_url == "https://example.invalid/y"
