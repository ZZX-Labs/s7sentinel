from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path


SUSPICIOUS_NAMES = {
    "snap7.dll", "libsnap7.so", "libsnap7.dylib", "snap7.py",
}
PY_EXTENSIONS = {".py", ".pyw"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def installed_snap7() -> list[dict]:
    out = []
    for dist_name in ("python-snap7", "snap7"):
        try:
            version = importlib.metadata.version(dist_name)
        except importlib.metadata.PackageNotFoundError:
            continue
        out.append({
            "type": "installed_package",
            "name": dist_name,
            "version": version,
            "reason": "AA26-231A specifically calls out snap7.dll/python-snap7; verify this installation is authorized.",
        })
    return out


def scan_roots(roots: list[str], max_files: int = 20000, hash_matches: bool = False) -> dict:
    artifacts = installed_snap7()
    scanned = 0
    truncated = False
    for root_s in roots:
        root = Path(root_s).expanduser().resolve()
        if not root.exists():
            artifacts.append({"type": "error", "path": str(root), "reason": "root does not exist"})
            continue
        paths = [root] if root.is_file() else root.rglob("*")
        for path in paths:
            if scanned >= max_files:
                truncated = True
                break
            if not path.is_file():
                continue
            scanned += 1
            name = path.name.lower()
            reason = ""
            if name in SUSPICIOUS_NAMES or "python_snap7" in name or "python-snap7" in name:
                reason = "Snap7-related filename"
            elif path.suffix.lower() in PY_EXTENSIONS:
                try:
                    if path.stat().st_size <= 2 * 1024 * 1024:
                        text = path.read_text(encoding="utf-8", errors="ignore").lower()
                        if "import snap7" in text or "from snap7" in text or "snap7.dll" in text:
                            reason = "Python source references snap7/Snap7 DLL"
                except OSError:
                    pass
            if reason:
                item = {
                    "type": "file_artifact",
                    "path": str(path),
                    "reason": reason,
                    "disposition": "Review whether this file is an approved engineering/monitoring component. Presence alone is not proof of compromise.",
                }
                if hash_matches:
                    try:
                        item["sha256"] = _sha256(path)
                    except OSError as e:
                        item["hash_error"] = str(e)
                artifacts.append(item)
        if truncated:
            break
    return {
        "scanned_files": scanned,
        "truncated": truncated,
        "artifacts": artifacts,
    }
