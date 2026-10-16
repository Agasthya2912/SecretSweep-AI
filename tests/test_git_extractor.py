"""Tests for scanner/git_extractor.py, exercised against a small public repo
(https://github.com/trufflesecurity/test_keys) that trufflesecurity maintains
specifically for testing secret scanners — it contains real-looking fake keys,
including keys that were added in one commit and deleted in a later one.
"""

from pathlib import Path

import pytest

from scanner.git_extractor import GitExtractor
from scanner.models import CommitData, DiffLine

TEST_REPO_URL = "https://github.com/trufflesecurity/test_keys"
KNOWN_MERGE_COMMIT = "1fc0463f2fc2233549c5f6a8a57bb5e2185cb20c"


@pytest.fixture(scope="module")
def extractor(tmp_path_factory: pytest.TempPathFactory) -> GitExtractor:
    """Clone the test repo once and share it across every test in this module."""
    local_path = tmp_path_factory.mktemp("test_keys_repo")
    ext = GitExtractor(TEST_REPO_URL, str(local_path))
    ext.clone_repo()
    return ext


@pytest.fixture(scope="module")
def all_commits(extractor: GitExtractor) -> list[CommitData]:
    return list(extractor.extract_all_commits())


def test_clone_repo_works(extractor: GitExtractor) -> None:
    assert extractor.repo is not None
    assert (Path(extractor.local_path) / ".git").exists()


def test_clone_repo_skips_if_already_cloned(extractor: GitExtractor, caplog) -> None:
    caplog.clear()
    with caplog.at_level("INFO"):
        extractor.clone_repo()
    assert any("skipping clone" in message for message in caplog.messages)


def test_extract_all_commits_returns_commits(all_commits: list[CommitData]) -> None:
    assert len(all_commits) > 0
    assert all(isinstance(c, CommitData) for c in all_commits)


def test_extract_all_commits_is_chronological_oldest_first(all_commits: list[CommitData]) -> None:
    timestamps = [c.timestamp for c in all_commits]
    assert timestamps == sorted(timestamps)


def test_extract_all_commits_skips_merge_commits(all_commits: list[CommitData]) -> None:
    hashes = {c.hash for c in all_commits}
    assert KNOWN_MERGE_COMMIT not in hashes


def test_extract_diff_lines_catches_added_secrets(
    extractor: GitExtractor, all_commits: list[CommitData]
) -> None:
    added_content = []
    for commit in all_commits:
        diff_lines = extractor.extract_diff_lines(commit)
        added_content.extend(dl.content for dl in diff_lines if dl.change_type == "added")

    assert any("AKIA" in content for content in added_content), (
        "expected at least one added line containing a fake AWS access key"
    )


def test_deleted_lines_are_captured(
    extractor: GitExtractor, all_commits: list[CommitData]
) -> None:
    deleted_content = []
    for commit in all_commits:
        diff_lines = extractor.extract_diff_lines(commit)
        deleted_content.extend(dl.content for dl in diff_lines if dl.change_type == "deleted")

    assert any("AKIA" in content for content in deleted_content), (
        "expected the AWS key removed in the 'woops, some keys' commit to appear as a deleted line"
    )


def test_extract_diff_lines_line_numbers_are_positive(
    extractor: GitExtractor, all_commits: list[CommitData]
) -> None:
    for commit in all_commits:
        for dl in extractor.extract_diff_lines(commit):
            assert dl.line_number >= 1
            assert dl.commit_hash == commit.hash


def test_binary_files_are_skipped(tmp_path: Path) -> None:
    """The remote fixture repo has no binary files, so exercise this against a
    throwaway local repo with a binary blob committed alongside a text file."""
    import git as gitmodule

    repo_path = tmp_path / "binary_repo"
    repo_path.mkdir()
    repo = gitmodule.Repo.init(repo_path)
    repo.config_writer().set_value("user", "name", "Test").release()
    repo.config_writer().set_value("user", "email", "test@example.com").release()

    (repo_path / "image.png").write_bytes(bytes(range(256)) * 4)
    (repo_path / "secret.txt").write_text("api_key = AKIAABCDEFGHIJKLMNOP\n")
    repo.index.add(["image.png", "secret.txt"])
    repo.index.commit("add binary and text file")

    extractor = GitExtractor(str(repo_path), str(repo_path))
    extractor.repo = repo

    commits = list(extractor.extract_all_commits())
    assert len(commits) == 1

    diff_lines = extractor.extract_diff_lines(commits[0])
    file_paths = {dl.file_path for dl in diff_lines}

    assert "image.png" not in file_paths
    assert "secret.txt" in file_paths
    assert any("AKIA" in dl.content for dl in diff_lines if dl.file_path == "secret.txt")


def test_get_file_at_commit_returns_content(
    extractor: GitExtractor, all_commits: list[CommitData]
) -> None:
    last_commit = all_commits[-1]
    file_path = last_commit.files_changed[0]
    content = extractor.get_file_at_commit(file_path, last_commit.hash)
    assert isinstance(content, str)
    assert content != ""


def test_get_file_at_commit_returns_empty_for_missing_file(
    extractor: GitExtractor, all_commits: list[CommitData]
) -> None:
    content = extractor.get_file_at_commit("does/not/exist.txt", all_commits[-1].hash)
    assert content == ""


def test_get_repo_stats_reports_expected_fields(extractor: GitExtractor) -> None:
    stats = extractor.get_repo_stats()
    # Reachable from HEAD: 6 commits (includes the merge commit itself; the
    # standalone "Create README.md" commit lives on an unmerged sibling branch).
    assert stats["total_commits"] == 6
    assert stats["total_authors"] >= 1
    assert stats["date_range"]["oldest"] is not None
    assert stats["date_range"]["newest"] is not None
    assert stats["total_files"] > 0
    assert stats["repo_size_mb"] >= 0
