"""Unit tests for Git change analyzer."""

import subprocess
from pathlib import Path

from vibeci.engine.diff.analyzer import GitChangeAnalyzer


def test_git_change_analyzer_on_untracked_and_modified_files(tmp_path: Path):
    # Initialize a temporary git repository
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), check=True)

    # Commit initial file
    f1 = tmp_path / "initial.py"
    f1.write_text("print('hello')\n")
    subprocess.run(["git", "add", "initial.py"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(tmp_path), check=True, stdout=subprocess.DEVNULL)

    # 1. Test clean state
    analyzer = GitChangeAnalyzer(tmp_path)
    res = analyzer.analyze()
    assert res.is_git_repo is True
    assert res.has_changes is False

    # 2. Modify f1
    f1.write_text("print('modified')\n")
    # Add untracked f2
    f2 = tmp_path / "new_file.py"
    f2.write_text("print('new')\n")

    res2 = analyzer.analyze()
    assert res2.has_changes is True
    assert len(res2.files) == 2
    rel_names = res2.relative_files
    assert "initial.py" in rel_names
    assert "new_file.py" in rel_names


def test_git_change_analyzer_test_file_matching(tmp_path: Path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), check=True)

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    smoke_tester = src_dir / "smoke_tester.py"
    smoke_tester.write_text("class SmokeTester: pass\n")

    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_smoke_tester = tests_dir / "test_smoke_tester.py"
    test_smoke_tester.write_text("def test_smoke(): pass\n")

    analyzer = GitChangeAnalyzer(tmp_path)
    res = analyzer.analyze()

    # smoke_tester.py itself should NOT be treated as a test file,
    # but test_smoke_tester.py should be detected as its related test file!
    related_stems = [p.stem for p in res.related_test_files]
    assert "test_smoke_tester" in related_stems
    assert "smoke_tester" not in related_stems

