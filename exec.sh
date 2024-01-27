#!/bin/bash
source ~/venv/bin/activate
python merge.py
git add .
git commit -m "update"
git push