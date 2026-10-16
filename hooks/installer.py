"""Installs/uninstalls the SecretSweep AI pre-commit hook into a repo's .git/hooks/."""

from pathlib import Path

SIGNATURE = "# Installed by: secretsweep"

HOOK_SCRIPT = f"""#!/bin/sh
# SecretSweep AI pre-commit hook
{SIGNATURE}
python -m hooks.hook
exit $?
"""


def _hook_path(repo_path: str) -> Path:
    return Path(repo_path) / ".git" / "hooks" / "pre-commit"


def install_hook(repo_path: str = ".") -> bool:
    """Write the pre-commit shim into .git/hooks/pre-commit and make it executable."""
    hooks_dir = Path(repo_path) / ".git" / "hooks"
    if not hooks_dir.exists():
        hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text(HOOK_SCRIPT, encoding="utf-8", newline="\n")

    try:
        hook_path.chmod(0o755)
    except OSError:
        pass  # best-effort on platforms without a meaningful executable bit

    return True


def uninstall_hook(repo_path: str = ".") -> bool:
    """Remove .git/hooks/pre-commit only if it carries the SecretSweep AI signature."""
    hook_path = _hook_path(repo_path)
    if not hook_path.exists():
        return False

    try:
        content = hook_path.read_text(encoding="utf-8")
    except OSError:
        return False

    if SIGNATURE not in content:
        return False

    hook_path.unlink()
    return True


def check_hook_installed(repo_path: str = ".") -> bool:
    """Return True if a SecretSweep AI-installed pre-commit hook is present."""
    hook_path = _hook_path(repo_path)
    if not hook_path.exists():
        return False

    try:
        content = hook_path.read_text(encoding="utf-8")
    except OSError:
        return False

    return SIGNATURE in content
