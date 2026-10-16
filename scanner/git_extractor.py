"""Extracts full Git history: commits, diffs, blobs, and author metadata."""

import logging
import re
import time
from pathlib import Path
from typing import Generator, List, Optional

from git import GitCommandError, InvalidGitRepositoryError, NoSuchPathError, NULL_TREE, Repo
from git.diff import Diff
from git.exc import BadName

from scanner.models import CommitData, DiffLine

logger = logging.getLogger(__name__)

MAX_FILE_SIZE_BYTES = 1_000_000  # 1 MB — files larger than this are skipped with a warning
CLONE_MAX_RETRIES = 3
CLONE_RETRY_BACKOFF_SECONDS = 2
PROGRESS_LOG_INTERVAL = 100

_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitExtractor:
    """Clones a Git repository and extracts its commit history for secret scanning."""

    def __init__(self, repo_url: str, local_path: str) -> None:
        """Store the source repo URL and the local filesystem path to clone it into."""
        self.repo_url = repo_url
        self.local_path = local_path
        self.repo: Optional[Repo] = None

    def clone_repo(self) -> None:
        """Clone repo_url into local_path, retrying up to 3 times on network failure.

        If a valid Git repository already exists at local_path, cloning is skipped and
        the existing repository is opened in place.
        """
        path = Path(self.local_path)
        if path.exists():
            try:
                self.repo = Repo(self.local_path)
                logger.info("Repository already cloned at %s, skipping clone", self.local_path)
                return
            except (InvalidGitRepositoryError, NoSuchPathError):
                logger.warning(
                    "%s exists but is not a valid Git repository; proceeding with clone",
                    self.local_path,
                )

        path.parent.mkdir(parents=True, exist_ok=True)

        last_error: Optional[Exception] = None
        for attempt in range(1, CLONE_MAX_RETRIES + 1):
            try:
                logger.info(
                    "Cloning %s into %s (attempt %d/%d)",
                    self.repo_url,
                    self.local_path,
                    attempt,
                    CLONE_MAX_RETRIES,
                )
                self.repo = Repo.clone_from(self.repo_url, self.local_path)
                logger.info("Clone complete: %s", self.local_path)
                return
            except GitCommandError as exc:
                last_error = exc
                logger.warning(
                    "Clone attempt %d/%d failed for %s: %s",
                    attempt,
                    CLONE_MAX_RETRIES,
                    self.repo_url,
                    exc,
                )
                if attempt < CLONE_MAX_RETRIES:
                    time.sleep(CLONE_RETRY_BACKOFF_SECONDS * attempt)

        raise ConnectionError(
            f"Failed to clone {self.repo_url} after {CLONE_MAX_RETRIES} attempts"
        ) from last_error

    def _require_repo(self) -> Repo:
        """Return the open Repo handle, raising if clone_repo() hasn't run yet."""
        if self.repo is None:
            raise RuntimeError("Repository not cloned yet — call clone_repo() first")
        return self.repo

    def extract_all_commits(self) -> Generator[CommitData, None, None]:
        """Yield every non-merge commit reachable from HEAD, oldest first.

        A generator is used instead of a list so that repositories with very long
        histories can be processed without holding every commit in memory at once.
        """
        repo = self._require_repo()

        if repo.head.is_detached:
            branch_name = repo.head.commit.hexsha[:7]
        else:
            branch_name = repo.active_branch.name

        try:
            head_commit = repo.head.commit
        except ValueError:
            # Empty repository — no commits, no HEAD to walk.
            logger.info("Repository %s has no commits", self.local_path)
            return

        commit_iter = repo.iter_commits(rev=head_commit, reverse=True)

        processed = 0
        for commit in commit_iter:
            if len(commit.parents) > 1:
                # Merge commit — its content is a union of already-seen parent history.
                continue

            yield CommitData(
                hash=commit.hexsha,
                author_name=commit.author.name or "",
                author_email=commit.author.email or "",
                timestamp=commit.committed_datetime,
                message=commit.message.strip(),
                branch=branch_name,
                files_changed=list(commit.stats.files.keys()),
            )

            processed += 1
            if processed % PROGRESS_LOG_INTERVAL == 0:
                logger.info("Processed %d commits", processed)

    def extract_diff_lines(self, commit: CommitData) -> List[DiffLine]:
        """Return every added, deleted, and context line in commit's diff against its parent.

        Deleted lines are included deliberately: a secret removed from the working tree
        in this commit is still present in the parent revision and therefore still
        recoverable from repository history. The initial commit (no parent) is diffed
        against Git's empty-tree object. Binary files and files over 1 MB are skipped.
        """
        repo = self._require_repo()
        commit_obj = repo.commit(commit.hash)

        if commit_obj.parents:
            # parent -> commit, so '-' lines are true deletions and '+' are true additions.
            diff_index = commit_obj.parents[0].diff(commit_obj, create_patch=True)
        else:
            # Initial commit: git-diff-tree convention, self.diff(NULL_TREE) diffs
            # this commit against the empty tree with correct add/delete signs.
            diff_index = commit_obj.diff(NULL_TREE, create_patch=True)

        diff_lines: List[DiffLine] = []
        for diff_item in diff_index:
            file_path = diff_item.b_path or diff_item.a_path
            if diff_item.renamed_file:
                file_path = f"{diff_item.rename_from} -> {diff_item.rename_to}"

            oversized = False
            for blob in (diff_item.a_blob, diff_item.b_blob):
                if blob is not None and blob.size > MAX_FILE_SIZE_BYTES:
                    logger.warning(
                        "Skipping %s in commit %s: file exceeds 1MB (%d bytes)",
                        file_path,
                        commit.hash,
                        blob.size,
                    )
                    oversized = True
                    break
            if oversized:
                continue

            diff_lines.extend(self._parse_patch(diff_item, file_path, commit))

        return diff_lines

    def _parse_patch(self, diff_item: Diff, file_path: str, commit: CommitData) -> List[DiffLine]:
        """Parse a single diff item's unified-diff patch text into DiffLine records."""
        raw_patch = diff_item.diff
        if raw_patch is None:
            return []  # e.g. pure rename or mode change with no content diff

        if isinstance(raw_patch, bytes):
            if raw_patch.startswith(b"Binary files") or b"\x00" in raw_patch[:8000]:
                logger.debug("Skipping binary file %s in commit %s", file_path, commit.hash)
                return []
            patch_text = raw_patch.decode("utf-8", errors="replace")
        else:
            patch_text = raw_patch

        lines: List[DiffLine] = []
        old_line_no = 0
        new_line_no = 0

        for raw_line in patch_text.splitlines():
            hunk_match = _HUNK_HEADER_RE.match(raw_line)
            if hunk_match:
                old_line_no = int(hunk_match.group(1))
                new_line_no = int(hunk_match.group(2))
                continue

            if not raw_line:
                continue

            marker = raw_line[0]
            content = raw_line[1:]

            if marker == "+" and not raw_line.startswith("+++"):
                lines.append(
                    DiffLine(
                        file_path=file_path,
                        line_number=new_line_no,
                        content=content,
                        change_type="added",
                        commit_hash=commit.hash,
                        author_email=commit.author_email,
                    )
                )
                new_line_no += 1
            elif marker == "-" and not raw_line.startswith("---"):
                lines.append(
                    DiffLine(
                        file_path=file_path,
                        line_number=old_line_no,
                        content=content,
                        change_type="deleted",
                        commit_hash=commit.hash,
                        author_email=commit.author_email,
                    )
                )
                old_line_no += 1
            elif marker == " ":
                lines.append(
                    DiffLine(
                        file_path=file_path,
                        line_number=new_line_no,
                        content=content,
                        change_type="context",
                        commit_hash=commit.hash,
                        author_email=commit.author_email,
                    )
                )
                old_line_no += 1
                new_line_no += 1

        return lines

    def get_file_at_commit(self, file_path: str, commit_hash: str) -> str:
        """Return the full text content of file_path as of commit_hash.

        Returns an empty string if the commit doesn't exist, the file isn't present
        at that commit, or the file's contents can't be decoded as text.
        """
        repo = self._require_repo()
        try:
            commit_obj = repo.commit(commit_hash)
        except (BadName, ValueError):
            logger.warning("Commit %s not found in %s", commit_hash, self.local_path)
            return ""

        try:
            blob = commit_obj.tree / file_path
        except KeyError:
            logger.warning("File %s not found at commit %s", file_path, commit_hash)
            return ""

        try:
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            logger.warning("Could not decode %s at commit %s as text", file_path, commit_hash)
            return ""

    def get_repo_stats(self) -> dict:
        """Return summary statistics: total commits, authors, date range, files, and size on disk."""
        repo = self._require_repo()

        try:
            all_commits = list(repo.iter_commits(rev=repo.head.commit))
        except ValueError:
            all_commits = []

        total_commits = len(all_commits)
        authors = {c.author.email for c in all_commits if c.author.email}

        if all_commits:
            newest_date = all_commits[0].committed_datetime
            oldest_date = all_commits[-1].committed_datetime
        else:
            newest_date = None
            oldest_date = None

        if total_commits > 0:
            total_files = sum(1 for item in repo.head.commit.tree.traverse() if item.type == "blob")
        else:
            total_files = 0

        repo_size_bytes = sum(f.stat().st_size for f in Path(self.local_path).rglob("*") if f.is_file())

        return {
            "total_commits": total_commits,
            "total_authors": len(authors),
            "date_range": {"oldest": oldest_date, "newest": newest_date},
            "total_files": total_files,
            "repo_size_mb": round(repo_size_bytes / (1024 * 1024), 2),
        }
