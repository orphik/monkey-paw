#!/usr/bin/env python3
"""Module entrypoint for `python3 -m studio`."""

from __future__ import annotations

from studio.server import main

if __name__ == "__main__":
    raise SystemExit(main())
