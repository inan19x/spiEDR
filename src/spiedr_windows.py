#!/usr/bin/env python3

import configparser
import csv
import ctypes
import hashlib
import logging
import os
import socket
import sys
import time
from pathlib import Path


# Windows API constants
FILE_ACTION_ADDED = 0x00000001
FILE_ACTION_REMOVED = 0x00000002
FILE_ACTION_MODIFIED = 0x00000003
FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
FILE_ACTION_RENAMED_NEW_NAME = 0x00000005

FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_SIZE = 0x00000008

FILE_LIST_DIRECTORY = 0x0001

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


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

        # Windows API function definitions.
        self.kernel32 = ctypes.windll.kernel32

        self.CreateFileW = self.kernel32.CreateFileW
        self.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p
        ]
        self.CreateFileW.restype = ctypes.c_void_p

        self.ReadDirectoryChangesW = (
            self.kernel32.ReadDirectoryChangesW
        )

        self.ReadDirectoryChangesW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_bool,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
            ctypes.c_void_p
        ]

        self.ReadDirectoryChangesW.restype = ctypes.c_bool

        self.CloseHandle = self.kernel32.CloseHandle
        self.CloseHandle.argtypes = [ctypes.c_void_p]
        self.CloseHandle.restype = ctypes.c_bool

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
            "SpiEDR-Windows"
        )

        self.logger.setLevel(logging.INFO)
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
        Wait until file size and modification time
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
        filepath = Path(filepath)

        try:
            if not filepath.is_file():
                return
        except OSError:
            return

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

    def open_directory(self):
        access = FILE_LIST_DIRECTORY

        share_mode = (
            0x00000001 |  # FILE_SHARE_READ
            0x00000002 |  # FILE_SHARE_WRITE
            0x00000004    # FILE_SHARE_DELETE
        )

        handle = self.CreateFileW(
            str(self.monitor_dir),
            access,
            share_mode,
            None,
            0x00000003,  # OPEN_EXISTING
            0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
            None
        )

        if handle == INVALID_HANDLE_VALUE:
            raise RuntimeError(
                f"Unable to monitor directory: "
                f"{self.monitor_dir}"
            )

        return handle

    def read_directory_changes(self, handle):
        buffer_size = 64 * 1024

        buffer = ctypes.create_string_buffer(
            buffer_size
        )

        bytes_returned = ctypes.c_uint32(0)

        notify_filter = (
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SIZE
        )

        success = self.ReadDirectoryChangesW(
            handle,
            buffer,
            buffer_size,
            self.recursive,
            notify_filter,
            ctypes.byref(bytes_returned),
            None,
            None
        )

        if not success:
            raise RuntimeError(
                "ReadDirectoryChangesW failed"
            )

        return buffer.raw[:bytes_returned.value]

    def parse_events(self, data):
        """
        Parse FILE_NOTIFY_INFORMATION structures.

        Structure:

        DWORD NextEntryOffset
        DWORD Action
        DWORD FileNameLength
        WCHAR FileName[...]
        """

        events = []
        offset = 0

        while offset < len(data):
            next_offset = int.from_bytes(
                data[offset:offset + 4],
                byteorder="little"
            )

            action = int.from_bytes(
                data[offset + 4:offset + 8],
                byteorder="little"
            )

            filename_length = int.from_bytes(
                data[offset + 8:offset + 12],
                byteorder="little"
            )

            filename_start = offset + 12
            filename_end = (
                filename_start + filename_length
            )

            filename = data[
                filename_start:filename_end
            ].decode(
                "utf-16-le",
                errors="replace"
            )

            events.append(
                (action, filename)
            )

            if next_offset == 0:
                break

            offset += next_offset

        return events

    def run(self):
        if os.name != "nt":
            raise RuntimeError(
                "spiedr_windows.py must be run on Windows."
            )

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

        handle = self.open_directory()

        print(
            f"SpiEDR Windows monitoring: "
            f"{self.monitor_dir}",
            flush=True
        )

        try:
            while True:
                data = self.read_directory_changes(
                    handle
                )

                events = self.parse_events(data)

                for action, filename in events:

                    if action in {
                        FILE_ACTION_ADDED,
                        FILE_ACTION_MODIFIED,
                        FILE_ACTION_RENAMED_NEW_NAME
                    }:
                        filepath = (
                            self.monitor_dir / filename
                        )

                        self.check_file(filepath)

                    # Removed files don't need to be hashed.
                    elif action == FILE_ACTION_REMOVED:
                        continue

                    elif action == FILE_ACTION_RENAMED_OLD_NAME:
                        continue

        except KeyboardInterrupt:
            print(
                "\nSpiEDR stopped.",
                flush=True
            )

        finally:
            self.CloseHandle(handle)


def main():
    config_path = "config/bunny.conf"

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

