#!/bin/bash
#
# Run Network Diagnostics Tool
# This script checks dependencies, makes the Python script executable,
# and runs the network diagnostics tool with the provided arguments.
# The tool generates a report on reachability and global routing table visibility.

# Directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PYTHON_SCRIPT="$SCRIPT_DIR/network_diagnostics.py"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    echo "Please install Python 3 and try again."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is required but not installed."
    echo "Please install pip3 and try again."
    exit 1
fi

# Install required dependencies
echo "Checking and installing required dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt"

# Make the Python script executable
if [ ! -x "$PYTHON_SCRIPT" ]; then
    echo "Making the Python script executable..."
    chmod +x "$PYTHON_SCRIPT"
fi

# Check if a target was provided
if [ $# -eq 0 ]; then
    echo "Error: No target specified."
    echo "Usage: $0 <target_ip_or_hostname> [--period PERIOD] [--output FILE]"
    echo "Where PERIOD is one of: 24h, 2d, 5d, 7d (default: 24h)"
    exit 1
fi

# Run the network diagnostics tool
echo "Running Network Diagnostics Tool for target: $1"
echo "=================================================="
python3 "$PYTHON_SCRIPT" "$@"
