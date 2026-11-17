#!/usr/bin/env python3
"""Launcher used by generated PATH shims. Kept outside the skill tree."""
import sys

from cordon.cli import main

raise SystemExit(main(sys.argv[1:]))
