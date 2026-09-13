#!/usr/bin/env python3

import configparser
import csv
import hashlib
import logging
import os
import socket
import sys
from pathlib import Path

from inotify_simple import INotify, flags


class SpiEDR:
    def __init__(self, config_path):
        self.config_path = Path(config_path)
        self.config = self.load_config()

        self.monitor_dir = Path(
            self.config["monitor"]["directory"]
        ).resolve()

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

        required_sections = ["monitor", "hash", "logging"]

        for section in required_sections:
            if section not in config:
                raise RuntimeError(
                    f"Missing configuration section: [{section}]"
                )

        return config

    def resolve_path(self, configured_path):
        path = Path(configured_path)

        if path.is_absolute():
            return path

        # Relative paths are resolved relative to the project/config
        # file's parent directory.
        return (self.config_path.parent.parent / path).resolve()

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

            if not required_fields.issubset(reader.fieldnames or []):
                raise RuntimeError(
                    "Invalid signature file header. "
                    "Expected: hash,type,name,severity"
                )

            for line_number, row in enumerate(reader, start=2):
                hash_value = row["hash"].strip().lower()
                detection_type = row["type"].strip()
                name = row["name"].strip()
                severity = row["severity"].strip().upper()

                if not hash_value:
                    continue

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
                        f"Invalid severity at line {line_number}: "
                        f"{severity}"
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

        self.logger = logging.getLogger("SpiEDR")
        self.logger.setLevel(logging.INFO)

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

            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()

            return ip

        except OSError:
            return "0.0.0.0"

    def calculate_hash(self, filepath):
        hasher = hashlib.new(self.hash_algorithm)

        try:
            with filepath.open("rb") as f:
                while chunk := f.read(1024 * 1024):
                    hasher.update(chunk)

            return hasher.hexdigest().lower()

        except (OSError, PermissionError):
            return None

    def alert(self, filepath, hash_value, signature):
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
        filepath = Path(filepath)

        if not filepath.is_file():
            return

        hash_value = self.calculate_hash(filepath)

        if hash_value is None:
            return

        signature = self.signatures.get(hash_value)

        # Unmatched hashes are intentionally silent.
        if signature is None:
            return

        self.alert(
            filepath,
            hash_value,
            signature
        )

    def add_watch(self, inotify, directory):
        try:
            inotify.add_watch(
                str(directory),
                flags.CLOSE_WRITE | flags.MOVED_TO
            )
        except OSError:
            return

    def setup_watches(self, inotify):
        self.add_watch(
            inotify,
            self.monitor_dir
        )

        if not self.recursive:
            return

        for root, dirs, _files in os.walk(self.monitor_dir):
            for directory in dirs:
                self.add_watch(
                    inotify,
                    Path(root) / directory
                )

    def run(self):
        inotify = INotify()

        self.setup_watches(inotify)

        print(
            f"SpiEDR monitoring: {self.monitor_dir}",
            flush=True
        )

        while True:
            events = inotify.read()

            for event in events:
                event_flags = flags.from_mask(event.mask)

                if not (
                    flags.CLOSE_WRITE in event_flags
                    or flags.MOVED_TO in event_flags
                ):
                    continue

                # Find the directory associated with the watch.
                # For this first POC, event.path is sufficient for
                # the watched directory returned by inotify-simple.
                #
                # The complete recursive watch handling will be
                # improved in the next iteration.
                for root, _dirs, _files in os.walk(
                    self.monitor_dir
                ):
                    filepath = Path(root) / event.name

                    if filepath.exists():
                        self.check_file(filepath)
                        break


def main():
    config_path = "config/spiedr.conf"

    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    try:
        edr = SpiEDR(config_path)
        edr.run()

    except KeyboardInterrupt:
        print("\nSpiEDR stopped.")

    except Exception as e:
        print(
            f"SpiEDR ERROR: {e}",
            file=sys.stderr
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

