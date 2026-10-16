"""Regex pattern definitions for known secret formats.

Each entry is a dict with:
    name           — human-readable pattern name
    pattern        — raw regex string (compiled by PatternScanner)
    group          — one of "cloud" | "scm_ci" | "payment" | "auth_crypto" | "database" | "generic"
    severity_hint  — CRITICAL | HIGH | MEDIUM | LOW, fed into the severity engine later
    description    — what the pattern targets

Patterns that need to isolate the actual secret value from surrounding
prefix text (e.g. `api_key = "..."`) wrap that value in a capturing group;
PatternScanner uses group(1) when present, otherwise the whole match.
"""

SECRET_PATTERNS = [
    # --- Group 1: Cloud Providers ---------------------------------------------------
    {
        "name": "AWS Access Key ID",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "group": "cloud",
        "severity_hint": "CRITICAL",
        "description": "AWS Access Key ID",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws_secret(?:_access)?_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "group": "cloud",
        "severity_hint": "CRITICAL",
        "description": "AWS Secret Access Key",
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "group": "cloud",
        "severity_hint": "HIGH",
        "description": "Google API Key",
    },
    {
        "name": "Google OAuth Token",
        "pattern": r"ya29\.[0-9A-Za-z\-_]+",
        "group": "cloud",
        "severity_hint": "HIGH",
        "description": "Google OAuth Access Token",
    },
    {
        "name": "Azure Storage Key",
        "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,}",
        "group": "cloud",
        "severity_hint": "CRITICAL",
        "description": "Azure Storage Account connection string",
    },
    {
        "name": "GCP Service Account",
        "pattern": r"\"type\"\s*:\s*\"service_account\"",
        "group": "cloud",
        "severity_hint": "HIGH",
        "description": "GCP Service Account JSON key file",
    },
    # --- Group 2: Source Control & CI ------------------------------------------------
    {
        "name": "GitHub Personal Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9]{36,255}",
        "group": "scm_ci",
        "severity_hint": "CRITICAL",
        "description": "GitHub Personal Access Token",
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": r"gho_[A-Za-z0-9]{36}",
        "group": "scm_ci",
        "severity_hint": "HIGH",
        "description": "GitHub OAuth Access Token",
    },
    {
        "name": "GitHub App Token",
        "pattern": r"(?:ghu|ghs)_[A-Za-z0-9]{36}",
        "group": "scm_ci",
        "severity_hint": "HIGH",
        "description": "GitHub App user-to-server or server-to-server token",
    },
    {
        "name": "GitLab Token",
        "pattern": r"glpat-[A-Za-z0-9\-]{20}",
        "group": "scm_ci",
        "severity_hint": "HIGH",
        "description": "GitLab Personal Access Token",
    },
    {
        "name": "CircleCI Token",
        "pattern": r"(?i)circle[-_]?token\s*[:=]\s*['\"]?([a-fA-F0-9]{40})['\"]?",
        "group": "scm_ci",
        "severity_hint": "MEDIUM",
        "description": "CircleCI API token",
    },
    # --- Group 3: Payment & Communications --------------------------------------------
    {
        "name": "Stripe Live Secret Key",
        "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        "group": "payment",
        "severity_hint": "CRITICAL",
        "description": "Stripe live-mode secret key",
    },
    {
        "name": "Stripe Test Secret Key",
        "pattern": r"sk_test_[0-9a-zA-Z]{24}",
        "group": "payment",
        "severity_hint": "LOW",
        "description": "Stripe test-mode secret key",
    },
    {
        "name": "Twilio Account SID",
        "pattern": r"AC[a-zA-Z0-9]{32}",
        "group": "payment",
        "severity_hint": "MEDIUM",
        "description": "Twilio Account SID",
    },
    {
        "name": "Twilio Auth Token",
        "pattern": r"(?i)twilio[a-zA-Z_]*\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        "group": "payment",
        "severity_hint": "HIGH",
        "description": "Twilio Auth Token",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "group": "payment",
        "severity_hint": "HIGH",
        "description": "SendGrid API Key",
    },
    # --- Group 4: Auth & Crypto ---------------------------------------------------------
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+",
        "group": "auth_crypto",
        "severity_hint": "MEDIUM",
        "description": "JSON Web Token",
    },
    {
        "name": "RSA Private Key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "group": "auth_crypto",
        "severity_hint": "CRITICAL",
        "description": "RSA private key block",
    },
    {
        "name": "EC Private Key",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "group": "auth_crypto",
        "severity_hint": "CRITICAL",
        "description": "Elliptic curve private key block",
    },
    {
        "name": "PGP Private Key",
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "group": "auth_crypto",
        "severity_hint": "CRITICAL",
        "description": "PGP private key block",
    },
    {
        "name": "SSH Private Key",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "group": "auth_crypto",
        "severity_hint": "CRITICAL",
        "description": "OpenSSH private key block",
    },
    {
        "name": "Generic Bearer Token",
        "pattern": r"Bearer\s+([a-zA-Z0-9\-_]{20,})",
        "group": "auth_crypto",
        "severity_hint": "MEDIUM",
        "description": "Generic Bearer authorization token",
    },
    # --- Group 5: Databases --------------------------------------------------------------
    {
        "name": "MongoDB URI",
        "pattern": r"mongodb(?:\+srv)?://[^:]+:[^@]+@",
        "group": "database",
        "severity_hint": "HIGH",
        "description": "MongoDB connection URI with embedded credentials",
    },
    {
        "name": "PostgreSQL URI",
        "pattern": r"postgres(?:ql)?://[^:]+:[^@]+@",
        "group": "database",
        "severity_hint": "HIGH",
        "description": "PostgreSQL connection URI with embedded credentials",
    },
    {
        "name": "MySQL URI",
        "pattern": r"mysql://[^:]+:[^@]+@",
        "group": "database",
        "severity_hint": "HIGH",
        "description": "MySQL connection URI with embedded credentials",
    },
    {
        "name": "Redis URI with Password",
        "pattern": r"redis://:[^@]+@",
        "group": "database",
        "severity_hint": "HIGH",
        "description": "Redis connection URI with embedded password",
    },
    {
        "name": "Generic DB Password",
        "pattern": r"(?i)(?:db|database)_pass(?:word)?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "group": "database",
        "severity_hint": "MEDIUM",
        "description": "Generic database password assignment",
    },
    # --- Group 6: Generic High-Entropy -----------------------------------------------------
    {
        "name": "Generic API Key",
        "pattern": r"(?i)api_key\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
        "group": "generic",
        "severity_hint": "MEDIUM",
        "description": "Generic api_key assignment",
    },
    {
        "name": "Generic Secret",
        "pattern": r"(?i)secret\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "group": "generic",
        "severity_hint": "MEDIUM",
        "description": "Generic secret assignment",
    },
    {
        "name": "Generic Password",
        "pattern": r"(?i)password\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "group": "generic",
        "severity_hint": "MEDIUM",
        "description": "Generic password assignment",
    },
    {
        "name": "Generic Token",
        "pattern": r"(?i)token\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
        "group": "generic",
        "severity_hint": "MEDIUM",
        "description": "Generic token assignment",
    },
]
