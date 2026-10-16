"""Builds the labeled credential vs non-credential dataset used to fine-tune
the Layer 2 CodeBERT semantic classifier.

Primary source is SecretBench (https://github.com/setu1421/SecretBench), but
that dataset is not directly downloadable: per its README, the actual secrets
are gated behind a signed data-protection agreement and served through Google
BigQuery / Cloud Storage, which this environment has no credentials for.
try_download_secretbench() makes a best-effort, clearly-logged attempt and
falls back to create_synthetic_dataset() whenever real access isn't available.
"""

import json
import logging
import random
import string
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)

random.seed(1421)  # deterministic dataset across runs

SECRETBENCH_REPO_URL = "https://github.com/setu1421/SecretBench"

DEFAULT_OUTPUT_PATH = "data/secretbench_processed.jsonl"
DEFAULT_SPLIT_DIR = "data"
DEFAULT_NUM_SAMPLES = 520

_ALNUM = string.ascii_letters + string.digits


def _random_string(length: int, alphabet: str = _ALNUM) -> str:
    return "".join(random.choices(alphabet, k=length))


# --------------------------------------------------------------------------------------
# Context window construction
# --------------------------------------------------------------------------------------

_FILLER_LINES = [
    "import os",
    "import sys",
    "import json",
    "import logging",
    "",
    "logger = logging.getLogger(__name__)",
    "",
    "def initialize_client():",
    "    session = requests.Session()",
    "    session.headers.update({'User-Agent': 'internal-service'})",
    "    return session",
    "",
    "class ConfigLoader:",
    "    def __init__(self):",
    "        self.settings = {}",
    "",
    "    def load(self):",
    "        with open('config.yaml') as f:",
    "            return yaml.safe_load(f)",
    "",
    "# Application configuration values below",
    "DEBUG = False",
    "MAX_RETRIES = 3",
    "TIMEOUT_SECONDS = 30",
    "REGION = 'us-east-1'",
    "",
    "def connect_to_service():",
    "    client = ServiceClient()",
    "    client.connect()",
    "    return client",
    "",
    "def handle_request(request):",
    "    payload = request.get_json()",
    "    return process(payload)",
    "",
    "class UserRepository:",
    "    def find_by_id(self, user_id):",
    "        return self.db.query(User).get(user_id)",
    "",
    "if __name__ == '__main__':",
    "    main()",
]


def _build_code_snippet(flagged_line: str) -> str:
    """Embed flagged_line inside 14-19 lines of plausible surrounding code (15-20 total)."""
    total_lines = random.randint(15, 20)
    filler_count = total_lines - 1
    filler = random.choices(_FILLER_LINES, k=filler_count)
    insert_at = random.randint(0, filler_count)
    lines = filler[:insert_at] + [flagged_line] + filler[insert_at:]
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Positive (is_secret=True) generators
# --------------------------------------------------------------------------------------


def _gen_aws_access_key() -> Tuple[str, str, str]:
    key = "AKIA" + _random_string(16, string.ascii_uppercase + string.digits)
    var = random.choice(["aws_access_key_id", "AWS_ACCESS_KEY", "access_key"])
    return f'{var} = "{key}"', "aws_access_key", (
        "Valid AWS Access Key ID format: AKIA prefix followed by 16 uppercase alphanumerics"
    )


def _gen_database_uri() -> Tuple[str, str, str]:
    scheme = random.choice(["postgres", "mysql", "mongodb"])
    user = random.choice(["admin", "dbuser", "app_user", "svc_account"])
    password = _random_string(14)
    host = random.choice(["prod-db.internal", "10.0.4.22", "db.example.com"])
    return (
        f'DATABASE_URL = "{scheme}://{user}:{password}@{host}:5432/appdb"',
        "database_uri",
        "Database connection URI with a high-entropy embedded password",
    )


def _gen_jwt_token() -> Tuple[str, str, str]:
    header = urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload_obj = json.dumps({"sub": _random_string(8), "iat": random.randint(1_600_000_000, 1_700_000_000)})
    payload = urlsafe_b64encode(payload_obj.encode()).decode().rstrip("=")
    signature = _random_string(32)
    return (
        f'auth_token = "{header}.{payload}.{signature}"',
        "jwt_token",
        "Well-formed JWT: base64url header and payload segments joined by dots",
    )


def _gen_github_token() -> Tuple[str, str, str]:
    token = "ghp_" + _random_string(36)
    return (
        f'GITHUB_TOKEN = "{token}"',
        "github_token",
        "GitHub Personal Access Token with correct ghp_ prefix and 36-char body",
    )


def _gen_private_key_header() -> Tuple[str, str, str]:
    kind, header = random.choice(
        [
            ("RSA", "-----BEGIN RSA PRIVATE KEY-----"),
            ("EC", "-----BEGIN EC PRIVATE KEY-----"),
            ("OPENSSH", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        ]
    )
    return header, "private_key", f"{kind} private key PEM block header"


def _gen_high_entropy_credential() -> Tuple[str, str, str]:
    var = random.choice(["secret_key", "signing_key", "encryption_key", "client_secret"])
    value = _random_string(random.randint(20, 32), _ALNUM + "!@#$%^&*")
    return (
        f'{var} = "{value}"',
        "high_entropy_credential",
        "High Shannon-entropy value assigned to a credential-named variable",
    )


# --------------------------------------------------------------------------------------
# Negative (is_secret=False) generators
# --------------------------------------------------------------------------------------


def _gen_placeholder() -> Tuple[str, str, str]:
    var = random.choice(["api_key", "password", "token", "secret"])
    value = random.choice(
        ["changeme", "your_api_key_here", "example", "test123", "xxxxxxxx", "placeholder", "dummy_value"]
    )
    return f'{var} = "{value}"', "placeholder", "Obvious placeholder/example value, not a real credential"


def _gen_empty_declaration() -> Tuple[str, str, str]:
    var = random.choice(["api_key", "password", "secret_token", "db_password"])
    line = random.choice([f'{var} = ""', f"{var} = None", f"let {var};", f"String {var};"])
    return line, "empty_declaration", "Variable declared without an assigned value"


def _gen_comment_mention() -> Tuple[str, str, str]:
    line = random.choice(
        [
            "# TODO: load the password from the secrets manager, not hardcoded",
            "// remember to rotate the API key before deploying",
            "# password validation happens in auth_service.py",
            "/* secret rotation policy: every 90 days */",
        ]
    )
    return line, "comment_mention", "Comment referencing credentials conceptually, no actual secret value"


def _gen_low_entropy_string() -> Tuple[str, str, str]:
    var = random.choice(["token", "key", "secret"])
    value = random.choice(["aaaaaaaaaaaa", "11111111", "abababab", "00000000000"])
    return f'{var} = "{value}"', "low_entropy_string", "Low Shannon-entropy value, unlikely to be a real secret"


def _gen_fake_config_key() -> Tuple[str, str, str]:
    line = random.choice(
        [
            'feature_flag_key = "enable_dark_mode"',
            'cache_key = "user_session_prefix"',
            'config_key = "max_retry_count"',
        ]
    )
    return line, "config_key", "Ordinary configuration key name, not a credential"


def _gen_hash_or_checksum() -> Tuple[str, str, str]:
    value = _random_string(random.choice([32, 40, 64]), "0123456789abcdef")
    var = random.choice(["file_checksum", "sha256_hash", "md5_digest", "content_hash"])
    return (
        f'{var} = "{value}"',
        "hash_or_checksum",
        "Hex digest of a file hash/checksum — high entropy but not a credential",
    )


def _gen_version_or_date() -> Tuple[str, str, str]:
    value = random.choice(
        [
            f"v{random.randint(1, 9)}.{random.randint(0, 20)}.{random.randint(0, 20)}",
            f"2024-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
            f"build-{random.randint(1000, 9999)}",
        ]
    )
    var = random.choice(["app_version", "release_date", "build_id"])
    return f'{var} = "{value}"', "version_or_date", "Version number or date string, not a credential"


_POSITIVE_GENERATORS: List[Callable[[], Tuple[str, str, str]]] = [
    _gen_aws_access_key,
    _gen_database_uri,
    _gen_jwt_token,
    _gen_github_token,
    _gen_private_key_header,
    _gen_high_entropy_credential,
]

_NEGATIVE_GENERATORS: List[Callable[[], Tuple[str, str, str]]] = [
    _gen_placeholder,
    _gen_empty_declaration,
    _gen_comment_mention,
    _gen_low_entropy_string,
    _gen_fake_config_key,
    _gen_hash_or_checksum,
    _gen_version_or_date,
]


def try_download_secretbench(output_dir: str = DEFAULT_SPLIT_DIR) -> Optional[str]:
    """Best-effort attempt to fetch the real SecretBench dataset.

    SecretBench's secrets are not published as a plain downloadable file: its
    README requires creating a Google Cloud account and signing a data
    protection agreement before BigQuery/Cloud Storage access is granted.
    Without those credentials there is nothing to programmatically fetch, so
    this always logs a clear reason and returns None so callers fall back to
    create_synthetic_dataset().
    """
    logger.warning(
        "SecretBench (%s) gates its data behind a signed data-protection "
        "agreement and Google BigQuery/Cloud Storage access — no credentials "
        "are configured, so it cannot be downloaded automatically. "
        "Falling back to the synthetic dataset generator.",
        SECRETBENCH_REPO_URL,
    )
    return None


def create_synthetic_dataset(output_path: str = DEFAULT_OUTPUT_PATH, num_samples: int = DEFAULT_NUM_SAMPLES) -> str:
    """Generate a labeled JSONL dataset of synthetic secret/non-secret code snippets.

    Draws evenly from 6 positive generators (real-looking fake AWS keys, DB URIs,
    JWTs, GitHub tokens, private key headers, high-entropy credential values) and
    7 negative generators (placeholders, empty declarations, comment mentions,
    low-entropy strings, fake config keys, hashes/checksums, version/date strings)
    to produce at least num_samples labeled examples with a roughly 50/50 split.
    """
    generators = [(fn, 1, True) for fn in _POSITIVE_GENERATORS] + [
        (fn, 0, False) for fn in _NEGATIVE_GENERATORS
    ]
    per_generator = max(1, num_samples // len(generators))

    samples = []
    for generator_fn, label, is_secret in generators:
        for _ in range(per_generator):
            flagged_line, secret_type, reason = generator_fn()
            samples.append(
                {
                    "code_snippet": _build_code_snippet(flagged_line),
                    "flagged_line": flagged_line,
                    "label": label,
                    "secret_type": secret_type,
                    "is_secret": is_secret,
                    "reason": reason,
                }
            )

    random.shuffle(samples)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        for sample in samples:
            f.write(json.dumps(sample) + "\n")

    logger.info("Wrote %d synthetic samples to %s", len(samples), output_path)
    return str(output_file)


def split_dataset(input_path: str, output_dir: str = DEFAULT_SPLIT_DIR) -> Tuple[str, str, str]:
    """Split a JSONL dataset 80/10/10 into train/val/test JSONL files."""
    with open(input_path, encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]

    random.shuffle(samples)
    n = len(samples)
    train_end = int(n * 0.8)
    val_end = train_end + int(n * 0.1)

    splits = {
        "train": samples[:train_end],
        "val": samples[train_end:val_end],
        "test": samples[val_end:],
    }

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {}
    for split_name, split_samples in splits.items():
        split_path = out_dir / f"{split_name}.jsonl"
        with split_path.open("w", encoding="utf-8") as f:
            for sample in split_samples:
                f.write(json.dumps(sample) + "\n")
        paths[split_name] = str(split_path)
        logger.info("Wrote %d samples to %s", len(split_samples), split_path)

    return paths["train"], paths["val"], paths["test"]


def print_dataset_stats(path: str) -> dict:
    """Compute and print total samples, positive/negative ratio, and secret_type distribution."""
    with open(path, encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]

    total = len(samples)
    positives = sum(1 for s in samples if s["label"] == 1)
    negatives = total - positives

    type_counts: dict = {}
    for sample in samples:
        type_counts[sample["secret_type"]] = type_counts.get(sample["secret_type"], 0) + 1

    print(f"Dataset: {path}")
    print(f"  Total samples:     {total}")
    print(f"  Positive (secret): {positives} ({positives / total:.1%})")
    print(f"  Negative (safe):   {negatives} ({negatives / total:.1%})")
    print("  secret_type distribution:")
    for secret_type, count in sorted(type_counts.items(), key=lambda kv: -kv[1]):
        print(f"    {secret_type:25} {count}")

    return {
        "total": total,
        "positives": positives,
        "negatives": negatives,
        "type_counts": type_counts,
    }


def prepare_dataset(
    output_path: str = DEFAULT_OUTPUT_PATH,
    split_dir: str = DEFAULT_SPLIT_DIR,
    num_samples: int = DEFAULT_NUM_SAMPLES,
) -> None:
    """Full pipeline: try SecretBench, fall back to synthetic, split, and print stats."""
    real_dataset = try_download_secretbench(split_dir)
    dataset_path = real_dataset or create_synthetic_dataset(output_path, num_samples)

    print_dataset_stats(dataset_path)
    train_path, val_path, test_path = split_dataset(dataset_path, split_dir)
    print(f"\nSplit into:\n  train: {train_path}\n  val:   {val_path}\n  test:  {test_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    prepare_dataset()
