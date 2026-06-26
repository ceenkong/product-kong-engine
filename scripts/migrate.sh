#!/bin/bash
python3 manage.py makemigrations && \
python3 manage.py makemigrations StaticAnalyzer && \
python3 manage.py migrate && \
python3 manage.py ensure_apk_editor_schema
