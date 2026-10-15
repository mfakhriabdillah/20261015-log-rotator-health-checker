```python
#!/usr/bin/env python3
"""Log Rotator & Health Checker — CLI tool for cloud/DevOps engineers."""

from __future__ import annotations

import argparse
import gzip
import glob
import logging
import os
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ───────────────────────── Data models ─────────────────────────

@dataclass
class LogRotationResult:
    """Tracks the outcome of a single rotation operation."""
    source: Path
    rotated_to: Optional[Path]
    original_size: int
    compressed_size: int
    timestamp: str
    success: bool
    error: Optional[str] = None

    def summary(self) -> str:
        ratio = (
            f"{(1 - self.compressed_size / self.original_size) * 100:.1f}%"
            if self.original_size else "N/A"
        )
        status = "OK" if self.success else f"FAILED: {self.error}"
        return (
            f"[{self.timestamp}] {self.source.name} "
            f"({self.original_size:,} → {self.compressed_size:,} bytes, "
            f"saved {ratio}) → {self.rotated_to or '-'} [{status}]"
        )


@dataclass
class HealthReport:
    """Aggregated health metrics for a set of log sources."""
    total_logs: int = 0
    healthy: int = 0
    warning: int = 0
    critical: int = 0
    total_size_mb: float = 0.0
    oldest_log_age_hours: float = 0.0
    issues: list[str] = field(default_factory=list)

    def add_log(self, path: Path, size_bytes: int, age_hours: float) -> None:
        self.total_logs += 1
        self.total_size_mb += size_bytes / (1024 * 1024)
        if age_hours > self.oldest_log_age_hours:
            self.oldest_log_age_hours = age_hours

    def classify(self, path: Path, size_bytes: int, age_hours: float) -> str:
        if age_hours > 720 or size_bytes > 10 * (1024 ** 3):
            self.critical += 1
            self.issues.append(f"CRITICAL: {path.name} — {age_hours:.1f}h old, "
                               f"{size_bytes / (1024 ** 3):.2f} GB")
            return "critical"
        if age_hours > 168 or size_bytes > 500 * (1024 ** 2):
            self.warning += 1
            self.issues.append(f"WARNING:  {path.name} — {age_hours:.1f}h old, "
                               f"{size_bytes / (1024 ** 2):.1f} MB")
            return "warning"
        self.healthy += 1
        return "healthy"

    def summary(self) -> str:
        lines = [
            "═══════════════════════════════════════",
            "  LOG HEALTH REPORT",
            "═══════════════════════════════════════",
            f"  Total log files : {self.total_logs}",
            f"  Healthy         : {self.healthy}",
            f"  Warnings        : {self.warning}",
            f"  Critical        : {self.critical}",
            f"  Total size      : {self.total_size_mb:.2f} MB",
            f"  Oldest age      : {self.oldest_log_age_hours:.1f} hours",
        ]
        if self.issues:
            lines.append("  Issues:")
            for issue in self.issues:
                lines.append(f"    • {issue}")
        lines.append("═══════════════════════════════════════")
        return "\n".join(lines)


# ───────────────────────── Helpers ─────────────────────────

def parse_size(size_str: str) -> int:
    """Parse a human-readable size string (e.g. '500MB', '2GB') into bytes."""
    units = {
        "B": 1, "KB": 1024, "MB": 1024 ** 2,
        "GB": 1024 ** 3, "TB": 1024 ** 4,
    }
    size_str = size_str.strip().upper()
    for suffix, multiplier in sorted(units.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(suffix):
            value = float(size_str[: -len(suffix)].strip())
            return int(value * multiplier)
    return int(float(size_str))


def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """Configure root and module loggers with optional file output."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)-7s] %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        handlers.append(fh)

    for h in handlers:
        h.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    root = logging.getLogger()
    root.setLevel(level)
    for h in handlers:
        root.addHandler(h)

    logging.getLogger("urllib3").setLevel(logging.WARNING)


def compact_timestamp() -> str:
    """Return a filesystem-safe timestamp string."""
    return datetime.now().strftime("%Y%m%dT%H%M%S")


def safe_write(path: Path, data: bytes) -> None:
    """Write data to *path* atomically via a temp file + rename."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(data)
        tmp.replace(path)
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ───────────────────────── Core operations ─────────────────────────

class LogRotator:
    """Rotates log files by compressing them with gzip and optionally deleting originals."""

    def __init__(
        self,
        max_size_bytes: int,
        max_age_hours: float,
        compress: bool = True,
        keep_original: bool = False,
        archive_dir: Optional[str] = None,
    ) -> None:
        self.max_size_bytes = max_size_bytes
        self.max_age_hours = max_age_hours
        self.compress = compress
        self.keep_original = keep_original
        self.archive_dir = Path(archive_dir) if archive_dir else None
        self.results: list[LogRotationResult] = []

    def _archive_dest(self, source: Path) -> Path:
        if self.archive_dir is None:
            return source.parent / f"{source.name}.{compact_timestamp()}.gz"
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        return self.archive_dir / f"{source.name}.{compact_timestamp()}.gz"

    def _should_rotate(self, path: Path) -> bool:
        stat = path.stat()
        if stat.st_size > self.max_size_bytes:
            return True
        age = (time.time() - stat.st_mtime) / 3600
        return age > self.max_age_hours

    def rotate(self, path: Path) -> LogRotationResult:
        """Rotate a single log file. Returns a result record."""
        ts = datetime.now().isoformat(timespec="seconds")
        original_size = path.stat().st_size
        try:
            dest = self._archive_dest(path)
            if self.compress:
                with path.open("rb") as f_in, gzip.open(dest, "wb", mtime=0) as f_out:
                    shutil.copyfileobj(f_in, f_out, length=1024 * 1024)
            else:
                dest.write_bytes(path.read_bytes())
            compressed_size = dest.stat().st_size
            if not self.keep_original:
                path.unlink()
            return LogRotationResult(
                source=path, rotated_to=dest, original_size=original_size,
                compressed_size=compressed_size, timestamp=ts, success=True,
            )
        except Exception as exc:
            logger.error("Rotation failed for %s: %s", path, exc)
            return LogRotationResult(
                source=path, rotated_to=None, original_size=original_size,
                compressed_size=0, timestamp=ts, success=False, error=str(exc),
            )

    def rotate_glob(self, pattern: str) -> list[LogRotationResult]:
        """Rotate every file matching *pattern* that needs rotation."""
        results: list[LogRotationResult] = []
        for path in sorted(Path(".").glob(pattern)):
            if path.is_file() and self._should_rotate(path):
                logger.info("Rotating %s (%d bytes)", path, path.stat().st_size)
                results.append(self.rotate(path))
            else:
                logger.debug("Skipping %s — within thresholds", path)
        self.results.extend(results)
        return results


class HealthChecker:
    """Inspects log directories and produces health reports."""

    def __init__(self, max_age_hours: float = 720.0, max_size_bytes: int = 0) -> None:
        self.max_age_hours = max_age_hours
        self.max_size_bytes = max_size_bytes or float("inf")

    def check_path(self, path: Path) -> HealthReport:
        report = HealthReport()
        if path.is_file():
            report.add_log(path, path.stat().st_size,
                           (time.time() - path.stat().st_mtime) / 3600)
            report.classify(path, path.stat().st_size,
                            (time.time() - path.stat().st_mtime) / 3600)
        elif path.is_dir():
            for log_file in sorted(path.rglob("*")):
                if log_file.is_file():
                    stat = log_file.stat()
                    age_h = (time.time() - stat.st_mtime) / 3600
                    report.add_log(log_file, stat.st_size, age_h)
                    report.classify(log_file, stat.st_size, age_h)
        else:
            report.issues.append(f"NOT FOUND: {path}")
            report.critical += 1
        return report

    def check_glob(self, pattern: str) -> HealthReport:
        report = HealthReport()
        for path in sorted(Path(".").glob(pattern)):
            sub = self.check_path(path)
            report.total_logs += sub.total_logs
            report.healthy += sub.healthy
            report.warning += sub.warning
            report.critical += sub.critical
            report.total_size_mb += sub.total_size_mb
            if sub.oldest_log_age_hours > report.oldest_log_age_hours:
                report.oldest_log_age_hours = sub.oldest_log_age_hours
            report.issues.extend(sub.issues)
        return report


# ───────────────────────── CLI ─────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-rotator",
        description="Rotate and health-check log files for cloud/DevOps workloads.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s rotate --pattern "*.log" --max-size 500MB
  %(prog)s rotate --pattern "/var/log/app/*.log" --archive-dir /backups/logs
  %(prog)s health  --path /var/log/nginx --max-age 168h
  %(prog)s health  --glob "**/*.log" --verbose
""",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable DEBUG-level output to stderr.")
    parser.add_argument("--log-file", metavar="FILE",
                        help="Also write logs to this file.")

    sub = parser.add_subparsers(dest="command", title="commands", required=True)

    # ── rotate ──
    rot = sub.add_parser("rotate", help="Compress and rotate matching log files")
    rot.add_argument("--pattern", "-p", default="*.log",
                     help="Glob pattern for log files (default: *.log).")
    rot.add_argument("--max-size", "-s", default="100MB",
                     help="Rotate files larger than this size (default: 100MB).")
    rot.add_argument("--max-age", "-a", default="72h",
                     help="Rotate files older than this (default: 72h).")
    rot.add_argument("--no-compress", action="store_true",
                     help="Copy instead of gzip-compressing.")
    rot.add_argument("--keep-original", action="store_true",
                     help="Retain the original file after archiving.")
    rot.add_argument("--archive-dir", "-d", metavar="DIR",
                     help="Move compressed files to this directory.")
    rot.add_argument("--dry-run", action="store_true",
                     help="Show what would be rotated without changing anything.")

    # ── health ──
    chk = sub.add_parser("health", help="Check health of log files/directories")
    grp = chk.add_mutually_exclusive_group(required=True)
    grp.add_argument("--path", "-p", metavar="PATH",
                     help="Single file or directory to inspect.")
    grp.add_argument("--glob", "-g", metavar="PATTERN",
                     help="Glob pattern to search for log files.")
    grp.add_argument("--config", "-c", metavar="FILE",
                     help="JSON config with a 'paths' list.")
    chk.add_argument("--max-age", "-a", default="720h",
                     help="Flag files older than this as critical (default: 720h).")
    chk.add_argument("--warning-age", "-w", default="168h",
                     help="Flag files older than this as warning (default: 168h).")
    chk.add_argument("--json", action="store_true",
                     help="Output report in JSON format.")

    return parser


def _parse_duration(s: str) -> float:
    """Parse a duration string like '72h', '30m', '2d' into hours."""
    s = s.strip().lower()
    multipliers = {"h": 1, "m": 1 / 60, "d": 24, "w": 168}
    for suffix, mult in multipliers.items():
        if s.endswith(suffix):
            return float(s[: -len(suffix)]) * mult
    return float(s)


def cmd_rotate(args: argparse.Namespace) -> int:
    max_size = parse_size(args.max_size)
    max_age = _parse_duration(args.max_age)

    if args.dry_run:
        rotator = LogRotator(max_size, max_age)
        for path in sorted(Path(".").glob(args.pattern)):
            if path.is_file() and rotator._should_rotate(path):
                logger.info("[DRY-RUN] Would rotate: %s (%d bytes)",
                            path, path.stat().st_size)
        return 0

    rotator = LogRotator(
        max_size_bytes=max_size,
        max_age_hours=max_age,
        compress=not args.no_compress,
        keep_original=args.keep_original,
        archive_dir=args.archive_dir,
    )
    results = rotator.rotate_glob(args.pattern)

    ok = sum(1 for r in results if r.success)
    fail = len(results) - ok
    logger.info("Rotated %d file(s) — %d OK, %d failed.", len(results), ok, fail)
    for r in results:
        logger.debug(r.summary())

    return 1 if fail else 0


def cmd_health(args: argparse.Namespace) -> int:
    max_age = _parse_duration(args.max_age)
    warn_age = _parse_duration(args.warning_age)

    checker = HealthChecker(max_age_hours=max_age, max_size_bytes=0)

    if args.config:
        import json
        cfg = json.loads(Path(args.config).read_text())
        paths = cfg.get("paths", [])
    elif args.path:
        paths = [Path(args.path)]
    else:
        paths = list(Path(".").glob(args.glob))

    report = HealthReport()
    for p in paths:
        sub = checker.check_path(Path(p))
        report.total_logs += sub.total_logs
        report.healthy += sub.healthy
        report.warning += sub.warning
        report.critical += sub.critical
        report.total_size_mb += sub.total_size_mb
        if sub.oldest_log_age_hours > report.oldest_log_age_hours:
            report.oldest_log_age_hours = sub.oldest_log_age_hours
        report.issues.extend(sub.issues)

    if args.json:
        import json as _json
        payload = {
            "total_logs": report.total_logs,
            "healthy": report.healthy,
            "warning": report.warning,
            "critical": report.critical,
            "total_size_mb": round(report.total_size_mb, 2),
            "oldest_log_age_hours": round(report.oldest_log_age_hours, 2),
            "issues": report.issues,
            "status": "critical" if report.critical else ("warning" if report.warning else "healthy"),
        }
        print(_json.dumps(payload, indent=2))
    else:
        print(report.summary())

    if report.critical:
        return 2
    return 1 if report.warning else 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    try:
        if args.command == "rotate":
            return cmd_rotate(args)
        if args.command == "health":
            return cmd_health(args)
    except Exception as exc:
        logger.exception("Unhandled error: %s", exc)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```