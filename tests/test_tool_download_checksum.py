"""Pinned SHA-256 verification of downloaded tools."""
import hashlib

import pytest

from aspm_cli.tool import download
from aspm_cli.tool.download import (
    LINUX_TARBALL_SHA256,
    TRIVY_SHA256,
    TRIVY_VERSION,
    ChecksumMismatch,
    ToolDownloader,
)


@pytest.fixture
def downloader(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return ToolDownloader()


def test_matching_download_is_kept(tmp_path, downloader):
    source = tmp_path / "tool.bin"
    source.write_bytes(b"binary")
    dest = tmp_path / "out.bin"
    downloader._download_file(source.as_uri(), dest, hashlib.sha256(b"binary").hexdigest())
    assert dest.read_bytes() == b"binary"


def test_mismatching_download_is_deleted_and_refused(tmp_path, downloader):
    source = tmp_path / "tool.bin"
    source.write_bytes(b"tampered")
    dest = tmp_path / "out.bin"
    with pytest.raises(ChecksumMismatch):
        downloader._download_file(source.as_uri(), dest, hashlib.sha256(b"original").hexdigest())
    assert not dest.exists()


def test_no_pinned_hash_keeps_the_old_behaviour(tmp_path, downloader):
    source = tmp_path / "tool.bin"
    source.write_bytes(b"x")
    dest = tmp_path / "out.bin"
    downloader._download_file(source.as_uri(), dest)
    assert dest.exists()


def test_every_linux_bundle_url_has_a_pinned_hash():
    assert set(ToolDownloader.TOOL_URLS["Linux"]) == set(LINUX_TARBALL_SHA256)


def test_trivy_hashes_cover_the_assets_the_installers_download():
    for asset in (
        f"trivy_{TRIVY_VERSION}_macOS-64bit.tar.gz",
        f"trivy_{TRIVY_VERSION}_macOS-ARM64.tar.gz",
        f"trivy_{TRIVY_VERSION}_windows-64bit.zip",
    ):
        assert len(TRIVY_SHA256[asset]) == 64, asset


def test_a_failed_linux_bundle_install_reports_failure(tmp_path, downloader, monkeypatch):
    bad = tmp_path / "container.tar.gz"
    bad.write_bytes(b"not the pinned file")
    monkeypatch.setitem(ToolDownloader.TOOL_URLS["Linux"], "container", bad.as_uri())
    assert downloader._download_and_extract_tar_gz(bad.as_uri(), tmp_path / "bin", "container") is False
    assert download.LINUX_TARBALL_SHA256["container"]
