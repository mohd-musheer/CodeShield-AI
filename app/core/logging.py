import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_production_logging():
    """Configures automatic rotating log files for API requests, background scans, and errors."""
    log_dir = Path("runtime/logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    # 10MB limit per file, up to 5 historical logs
    max_bytes = 10 * 1024 * 1024
    backup_count = 5

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Clean default handlers
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # Console Handler for container stdout
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(logging.INFO)
    root_logger.addHandler(console)

    # API Log rotating handler
    api_handler = RotatingFileHandler(
        log_dir / "api.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8"
    )
    api_handler.setFormatter(formatter)
    api_handler.setLevel(logging.INFO)
    root_logger.addHandler(api_handler)

    # Errors Log rotating handler
    error_handler = RotatingFileHandler(
        log_dir / "errors.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8"
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.WARNING) # Warn and higher
    root_logger.addHandler(error_handler)

    # Scan log logger
    scan_logger = logging.getLogger("CodeShieldAI.Scanner")
    scan_logger.setLevel(logging.INFO)
    scan_logger.propagate = False # Prevent duplication to root

    scan_file_handler = RotatingFileHandler(
        log_dir / "scan.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8"
    )
    scan_file_handler.setFormatter(formatter)
    scan_logger.addHandler(scan_file_handler)

    # Also log to stdout for the container logs
    scan_console_handler = logging.StreamHandler()
    scan_console_handler.setFormatter(formatter)
    scan_logger.addHandler(scan_console_handler)

    print(f"[Logging] Setup production logs rotating handlers inside {log_dir}")
