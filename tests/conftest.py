#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pytest configuration for LibSurgeon tests.

This file is automatically loaded by pytest and sets up the Python path
to allow importing modules from the parent directory.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
