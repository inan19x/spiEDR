#!/usr/bin/env python3

import configparser
import csv
import hashlib
import logging
import socket
import subprocess
import sys
import time
from pathlib import Path


class SpiEDR:
    def __init__(self, config_path):
        self.config_path = Path(config_path).resolve()
        self.config = self.load_config()

        self.monitor_dir = Path(
            self.config["monitor"]["directory"]
        ).expanduser().resolve()

        self.recursive = self.config["monitor"].getboolean(
            "recursive",
            fallback=True
        )

        self.hash_algorithm = self.config["hash"]["algorithm"].lower()

        self.signature_file = self.resolve_path(
            self.config["hash"]["signature_file"]
        )

        self.log_file = self.resolve_path(
            self.config["logging"]["log_file"]
        )

        self.signatures = {}

        # Prevent repeated alerts for the same file/hash pair.
        self.alerted_files = set()

        self.hostname = socket.gethostname()
        self.srcip = self.get_src_ip()

        self.load_signatures()
        self.setup_logger()

    def load_config(self):
        if not self.config_path.exists():
            raise RuntimeError(
                f"Configuration file not found: {self.config_path}"
            )

        config = configparser.ConfigParser()
        config.read(self.config_path)

        required_sections = [
            "monitor",
            "hash",
            "logging"
        ]

        for section in required_sections:
            if section not in config:
                raise RuntimeError(
                    f"Missing configuration section: [{section}]"
                )

        return config

    def resolve_path(self, configured_path):
        path = Path(configured_path).expanduser()

        if path.is_absolute():
            return path

        # Resolve relative paths from the SpiEDR project root.
        return (
            self.config_path.parent.parent / path
        ).resolve()

    def load_signatures(self):
        if not self.signature_file.exists():
            raise RuntimeError(
                f"Signature file not found: {self.signature_file}"
            )

        with self.signature_file.open(
            "r",
            encoding="utf-8",
            newline=""
        ) as f:

            reader = csv.DictReader(f)

            required_fields = {
                "hash",
                "type",
                "name",
                "severity"
            }

            if not required_fields.issubset(
                reader.fieldnames or []
            ):
                raise RuntimeError(
                    "Invalid signature file header. "
                    "Expected: hash,type,name,severity"
                )

            for line_number, row in enumerate(
                reader,
                start=2
            ):
                hash_value = row["hash"].strip().lower()
                detection_type = row["type"].strip()
                name = row["name"].strip()
                severity = row["severity"].strip().upper()

                # Ignore empty lines.
                if not hash_value:
                    continue

                # SpiEDR v0.1 uses SHA-256.
                if len(hash_value) != 64:
                    raise RuntimeError(
                        f"Invalid SHA-256 at line {line_number}"
                    )

                try:
                    int(hash_value, 16)
                except ValueError:
                    raise RuntimeError(
                        f"Invalid hash at line {line_number}"
                    )

                if severity not in {
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL"
                }:
                    raise RuntimeError(
                        f"Invalid severity at line "
                        f"{line_number}: {severity}"
                    )

                if hash_value in self.signatures:
                    raise RuntimeError(
                        f"Duplicate hash at line {line_number}"
                    )

                self.signatures[hash_value] = {
                    "type": detection_type,
                    "name": name,
                    "severity": severity
                }

    def setup_logger(self):
        self.log_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.logger = logging.getLogger(
            "SpiEDR-MacOS"
        )

        self.logger.setLevel(logging.INFO)

        # Prevent duplicate handlers if the class is initialized
        # more than once.
        self.logger.handlers.clear()

        handler = logging.FileHandler(
            self.log_file,
            encoding="utf-8"
        )

        formatter = logging.Formatter(
            "%(asctime)s %(message)s",
            datefmt="%H:%M:%S"
        )

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def get_src_ip(self):
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            sock.connect(
                ("8.8.8.8", 80)
            )

            ip = sock.getsockname()[0]

            sock.close()

            return ip

        except OSError:
            return "0.0.0.0"

    def calculate_hash(self, filepath):
        try:
            hasher = hashlib.new(
                self.hash_algorithm
            )

            with open(
                filepath,
                "rb"
            ) as f:

                while True:
                    chunk = f.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    hasher.update(chunk)

            return hasher.hexdigest().lower()

        except (
            OSError,
            PermissionError
        ):
            return None

    def is_file_stable(
        self,
        filepath,
        checks=2,
        interval=0.5
    ):
        """
        Wait until the file size and modification time
        remain unchanged across multiple checks.
        """

        previous = None

        for _ in range(checks):
            try:
                stat = filepath.stat()

                current = (
                    stat.st_size,
                    stat.st_mtime_ns
                )

            except (
                OSError,
                PermissionError
            ):
                return False

            if previous is not None and current != previous:
                previous = current
                time.sleep(interval)
                continue

            previous = current
            time.sleep(interval)

        try:
            stat = filepath.stat()

            final_state = (
                stat.st_size,
                stat.st_mtime_ns
            )

            return final_state == previous

        except (
            OSError,
            PermissionError
        ):
            return False

    def alert(
        self,
        filepath,
        hash_value,
        signature
    ):
        alert_key = (
            str(filepath),
            hash_value
        )

        # Avoid repeated alerts for the same file/hash.
        if alert_key in self.alerted_files:
            return

        self.alerted_files.add(alert_key)

        message = (
            f"ALERT spiEDR: "
            f"signature={signature['name']} "
            f"type={signature['type']} "
            f"severity={signature['severity']} "
            f"hash={hash_value} "
            f"host={self.hostname} "
            f"srcip={self.srcip} "
            f"filepath={filepath}"
        )

        self.logger.info(message)

    def check_file(self, filepath):
        filepath = Path(filepath).expanduser()

        try:
            if not filepath.is_file():
                return
        except OSError:
            return

        # Don't hash a file while it is still being written.
        if not self.is_file_stable(filepath):
            return

        hash_value = self.calculate_hash(filepath)

        if hash_value is None:
            return

        signature = self.signatures.get(
            hash_value
        )

        # Unmatched hashes are intentionally silent.
        if signature is None:
            return

        self.alert(
            filepath,
            hash_value,
            signature
        )

    def start_fswatch(self):
        if not self.monitor_dir.exists():
            raise RuntimeError(
                f"Monitor directory does not exist: "
                f"{self.monitor_dir}"
            )

        if not self.monitor_dir.is_dir():
            raise RuntimeError(
                f"Monitor path is not a directory: "
                f"{self.monitor_dir}"
            )

        # Verify fswatch is available.
        try:
            subprocess.run(
                ["fswatch", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True
            )
        except (
            FileNotFoundError,
            subprocess.CalledProcessError
        ):
            raise RuntimeError(
                "fswatch is not installed. "
                "Install it with: brew install fswatch"
            )

        command = [
            "fswatch",
            "--event",
            "Created",
            "--event",
            "Updated",
            "--event",
            "Renamed",
            "--event",
            "MovedFrom",
            "--event",
            "MovedTo",
            "--format",
            "%p",
            str(self.monitor_dir)
        ]

        # fswatch is recursive by default.
        # Disable recursion when configured otherwise.
        if not self.recursive:
            command.insert(
                1,
                "--one-per-batch"
            )

        print(
            f"SpiEDR macOS monitoring: "
            f"{self.monitor_dir}",
            flush=True
        )

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        try:
            for line in process.stdout:
                filepath = line.strip()

                if not filepath:
                    continue

                self.check_file(filepath)

        except KeyboardInterrupt:
            print(
                "\nSpiEDR stopped.",
                flush=True
            )

        finally:
            process.terminate()

            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()

    def run(self):
        self.start_fswatch()


def main():
    config_path = "config/spiedr.conf"

    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    try:
        edr = SpiEDR(config_path)
        edr.run()

    except KeyboardInterrupt:
        print(
            "\nSpiEDR stopped.",
            flush=True
        )

    except Exception as e:
        print(
            f"SpiEDR ERROR: {e}",
            file=sys.stderr
        )

        sys.exit(1)


if __name__ == "__main__":
    main()

