#!/bin/bash
.venv/bin/python merge.py
git add .
git commit -m "update"
git push
