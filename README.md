# spiEDR

spiEDR is a simple cross-platform, playground-level EDR that monitors files and detects known signatures using SHA-256 hashes.

## Supported OS:<br/>
Linux — spiedr_linux.py<br/>
macOS — spiedr_macos.py<br/>
Windows — spiedr_windows.py<br/>

## Installation<br/>
### Linux<br/>
> python3 -m pip install -r requirements_linux.txt<br/><br/>

### macOS<br/>
> brew install fswatch<br/><br/>

### Windows<br/>
> No additional Python package is required.<br/><br/>

## Run<br/>
### Linux<br/>
> python3 src/spiedr_linux.py<br/><br/>

### macOS<br/>
> python3 src/spiedr_macos.py<br/><br/>

### Windows<br/>
> python src\spiedr_windows.py<br/><br/>

spiEDR monitors the directory configured in spiedr.conf.<br/>

Matched signatures are written to: logs/spiedr.log
