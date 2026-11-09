#!/usr/bin/env bash

OUTPUT_FILE="combined_code.txt"
TARGET_DIR="${1:-.}"

> "$OUTPUT_FILE"

find "$TARGET_DIR" -type f \
  ! -path '*/.*' \
  ! -path '*/node_modules/*' \
  ! -path '*/venv/*' \
  ! -path '*/__pycache__/*' \
  ! -name '__init__.py' \
  ! -path '*/build/*' \
  ! -path '*/dist/*' \
  ! -name "$OUTPUT_FILE" -print0 | while IFS= read -r -d '' file; do
    echo "========================================" >> "$OUTPUT_FILE"
    echo "FILE: $file" >> "$OUTPUT_FILE"
    echo "========================================" >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
    printf "\n\n" >> "$OUTPUT_FILE"
done

echo "Done! Combined code saved to $OUTPUT_FILE"