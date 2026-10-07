#!/usr/bin/env python3
"""Entry point for the ransomware-analyzer CLI."""
import sys
from analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
