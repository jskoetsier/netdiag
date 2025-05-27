# Network Diagnostics Tool - Installation Guide

This document provides detailed installation instructions for the Network Diagnostics Tool on various platforms.

## Prerequisites

The Network Diagnostics Tool requires:

- Python 3.6 or higher
- pip (Python package manager)
- Git (optional, for cloning the repository)

## Installation Methods

### Method 1: Quick Install (Recommended)

This method uses the provided shell script which automatically handles dependencies.

1. Clone or download the repository:
   ```bash
   git clone https://github.com/yourusername/network-diagnostics.git
   cd network-diagnostics
   ```

2. Make the shell script executable:
   ```bash
   chmod +x run_diagnostics.sh
   ```

3. Run the tool (the script will automatically install required dependencies):
   ```bash
   ./run_diagnostics.sh 8.8.8.8
   ```

### Method 2: Manual Installation

If you prefer to install dependencies manually:

1. Clone or download the repository:
   ```bash
   git clone https://github.com/yourusername/network-diagnostics.git
   cd network-diagnostics
   ```

2. Install required Python packages:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Make the Python script executable:
   ```bash
   chmod +x network_diagnostics.py
   ```

4. Run the tool:
   ```bash
   ./network_diagnostics.py 8.8.8.8
   ```

## Platform-Specific Instructions

### macOS

1. Install Python 3 (if not already installed):
   ```bash
   # Using Homebrew
   brew install python3

   # Or download from python.org
   # https://www.python.org/downloads/macos/
   ```

2. Install Git (if not already installed):
   ```bash
   brew install git
   ```

3. Follow the Quick Install or Manual Installation steps above.

### Linux (Debian/Ubuntu)

1. Install Python 3 and pip:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip git
   ```

2. Follow the Quick Install or Manual Installation steps above.

### Linux (RHEL/CentOS/Fedora)

1. Install Python 3 and pip:
   ```bash
   sudo dnf install python3 python3-pip git
   # or on older systems:
   # sudo yum install python3 python3-pip git
   ```

2. Follow the Quick Install or Manual Installation steps above.

### Windows

1. Install Python 3 from [python.org](https://www.python.org/downloads/windows/)
   - During installation, check "Add Python to PATH"

2. Install Git from [git-scm.com](https://git-scm.com/download/win)

3. Open Command Prompt or PowerShell:
   ```cmd
   git clone https://github.com/yourusername/network-diagnostics.git
   cd network-diagnostics
   pip install -r requirements.txt
   python network_diagnostics.py 8.8.8.8
   ```

## Docker Installation

You can also run the tool in a Docker container:

1. Build the Docker image:
   ```bash
   docker build -t network-diagnostics .
   ```

2. Run the tool in a container:
   ```bash
   docker run --rm network-diagnostics 8.8.8.8
   ```

## Troubleshooting

### Python Version Issues

If you have multiple Python versions installed, you may need to use `python3` and `pip3` explicitly:

```bash
python3 -m pip install -r requirements.txt
python3 ./network_diagnostics.py 8.8.8.8
```

### Permission Denied

If you encounter permission issues when running the script:

```bash
chmod +x run_diagnostics.sh
chmod +x network_diagnostics.py
```

### Missing Dependencies

If you see errors about missing modules:

```bash
pip3 install requests ipaddress
```

### Network Issues

The tool requires internet access to query various BGP data sources. If you're behind a corporate firewall or proxy, you may need to configure your proxy settings:

```bash
export HTTP_PROXY="http://proxy.example.com:8080"
export HTTPS_PROXY="http://proxy.example.com:8080"
```

## Updating

To update to the latest version:

```bash
git pull origin main
```

## Uninstallation

Since the tool doesn't install system-wide, you can simply delete the directory:

```bash
rm -rf network-diagnostics
```

## Next Steps

After installation, refer to the [README.md](README.md) file for usage instructions and examples.
