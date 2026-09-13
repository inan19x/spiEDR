spiEDR

spiEDR is a simple cross-platform EDR proof of concept that monitors files and detects known signatures using SHA-256 hashes.

Supported OS
Linux — bunnyedr_linux.py
macOS — bunnyedr_macos.py
Windows — bunnyedr_windows.py

Structure
spiEDR/
├── src/
│   ├── bunnyedr_linux.py
│   ├── bunnyedr_macos.py
│   └── bunnyedr_windows.py
├── config/
│   └── bunny.conf
├── signatures/
│   └── bunny-hash.txt
├── logs/
│   └── bunnyedr.log
├── requirements_linux.txt
├── requirements_macos.txt
└── README.md

Installation
Linux
python3 -m pip install -r requirements_linux.txt

macOS
brew install fswatch

Windows
No additional Python package is required.

Run
Linux
python3 src/bunnyedr_linux.py

macOS
python3 src/bunnyedr_macos.py

Windows
python src\bunnyedr_windows.py


spiEDR monitors the directory configured in bunny.conf.

Matched signatures are written to: logs/bunnyedr.log

Unmatched hashes are ignored.
