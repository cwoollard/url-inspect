"""Create a reproducible source archive, excluding build artifacts and local files."""
import gzip
import re
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    "Cargo.toml", "Cargo.lock", "README.md", "LICENSE", "CONTRIBUTING.md",
    "CHANGELOG.md", "RELEASING.md", "mise.toml", "rust-toolchain.toml", ".gitignore",
    ".gitattributes", ".editorconfig",
}
SOURCE_DIRS = {"src", "tests", "scripts", "packaging", ".github"}


def main():
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    version = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*)"', manifest, re.M)
    if not version:
        raise SystemExit("Cannot determine package version")
    output = ROOT / "dist" / ("url-inspect-v" + version.group(1) + "-source.tar.gz")
    output.parent.mkdir(exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            candidates = [ROOT / name for name in ROOT_FILES if (ROOT / name).is_file()]
            for directory in SOURCE_DIRS:
                if (ROOT / directory).is_dir():
                    candidates.extend((ROOT / directory).rglob("*"))
            for path in sorted(candidates):
                relative = path.relative_to(ROOT)
                if relative.parts[0] not in SOURCE_DIRS and relative.as_posix() not in ROOT_FILES:
                    continue
                if path.is_symlink() or not path.is_file() or any(part in {"__pycache__", ".DS_Store"} for part in relative.parts) or path.suffix == ".pyc":
                    continue
                info = archive.gettarinfo(str(path), arcname="url-inspect/" + relative.as_posix())
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                with path.open("rb") as source:
                    archive.addfile(info, source)
    print(output)


if __name__ == "__main__":
    main()
