#!/bin/bash
uv run merge.py
git add .
git commit -m "update"
git push
