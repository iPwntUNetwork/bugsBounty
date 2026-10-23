#!/usr/bin/env python3
"""Entrypoint alias delegating cleanly to `bughunter.py`."""
from bughunter import app, main

if __name__ == "__main__":
    main()
