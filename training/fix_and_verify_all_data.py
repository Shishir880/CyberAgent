import os
import re
import json
from test_parser import parse_entry_robust

folder = r"d:\ML-DL\tools\cyber_agent\training\all data"
files_to_fix = ["data3.json", "data4.json", "data5.json", "data6.json"]

for fname in files_to_fix:
    p = os.path.join(folder, fname)
    with open(p, "r", encoding="utf-8") as f:
        text = f.read()

    parts = re.split(r'\n  \{\s*\n\s*"id":', text)
    file_items = []
    for i, part in enumerate(parts):
        if i == 0 and not part.strip().startswith('{"id":'):
            continue
        candidate = '{\n    "id":' + part
        candidate = candidate.rstrip()
        if candidate.endswith(']'):
            candidate = candidate[:-1].rstrip()
        if candidate.endswith(','):
            candidate = candidate[:-1].rstrip()
        entry, mode = parse_entry_robust(candidate)
        file_items.append(entry)

    with open(p, "w", encoding="utf-8") as f:
        json.dump(file_items, f, indent=2, ensure_ascii=False)
    print(f"Fixed {fname}: {len(file_items)} items written as clean JSON!")

# Verify all files in all data folder now load directly with json.load
print("\n--- Verifying all files in 'all data' ---")
total_items = 0
for fname in sorted(os.listdir(folder)):
    if not fname.endswith(".json"):
        continue
    p = os.path.join(folder, fname)
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"  {fname:15s}: PASS ({len(data)} items)")
    total_items += len(data)

print(f"\n[+] Total items in all data folder: {total_items}")
