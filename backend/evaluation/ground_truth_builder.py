import os
import json
import subprocess
import requests
import time
from pathlib import Path

GITHUB_API = "https://api.github.com/repos/shellphish/how2heap/contents/"
RAW_BASE = "https://raw.githubusercontent.com/shellphish/how2heap/master/"

OUTPUT_DIR = Path("backend/evaluation/ground_truth")
BINARY_DIR = OUTPUT_DIR / "binaries"
LABEL_FILE = OUTPUT_DIR / "labels.json"
BUILD_REPORT = OUTPUT_DIR / "build_report.txt"
SOURCE_DIR = OUTPUT_DIR / "sources"

FILENAME_TO_CATEGORY = {
    "tcache_poisoning": "tcache_poisoning",
    "tcache_dup": "tcache_poisoning",
    "tcache_house_of_spirit": "house_of_spirit",
    "fastbin_dup": "fastbin_dup",
    "fastbin_dup_consolidate": "fastbin_dup",
    "fastbin_dup_into_stack": "fastbin_dup",
    "house_of_force": "house_of_force",
    "house_of_spirit": "house_of_spirit",
    "house_of_orange": "house_of_orange",
    "house_of_lore": "heap_exploitation",
    "house_of_einherjar": "heap_exploitation",
    "unsorted_bin_attack": "unsorted_bin_attack",
    "unsafe_unlink": "use_after_free",
    "overlapping_chunks": "heap_exploitation",
    "overlapping_chunks_2": "heap_exploitation",
    "poison_null_byte": "off_by_one",
    "null_byte_poison": "off_by_one",
    "use_after_free": "use_after_free",
    "double_free": "use_after_free",
    "heap_overflow": "heap_exploitation",
    "large_bin_attack": "heap_exploitation",
    "tcache_stashing_unlink_attack": "tcache_poisoning",
}

def fetch_how2heap_files() -> list:
    print("[GT Builder] Fetching how2heap file list...")
    try:
        resp = requests.get(GITHUB_API, timeout=30)
        resp.raise_for_status()
        files = resp.json()
        c_files = [f for f in files if isinstance(f, dict) and f.get("name", "").endswith(".c")]
        print(f"[GT Builder] Found {len(c_files)} .c files")
        return c_files
    except Exception as e:
        print(f"[GT Builder] Failed to fetch file list: {e}")
        return []

def compile_binary(source_path: Path, output_path: Path) -> bool:
    try:
        result = subprocess.run(
            ["gcc", "-o", str(output_path), str(source_path),
             "-no-pie", "-fno-stack-protector", "-w", "-lpthread"],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def build_ground_truth():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    BINARY_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_DIR.mkdir(parents=True, exist_ok=True)

    c_files = fetch_how2heap_files()
    if not c_files:
        print("[GT Builder] No files fetched. Check GitHub API connectivity.")
        return {}

    labels = {}
    build_results = []

    for file_info in c_files:
        filename = file_info["name"]
        stem = Path(filename).stem
        category = FILENAME_TO_CATEGORY.get(stem)

        if category is None:
            build_results.append(f"SKIPPED (no mapping): {filename}")
            continue

        raw_url = RAW_BASE + filename
        print(f"[GT Builder] Downloading {filename}...")
        try:
            resp = requests.get(raw_url, timeout=30)
            if resp.status_code != 200:
                build_results.append(f"DOWNLOAD FAILED: {filename}")
                continue
        except Exception as e:
            build_results.append(f"DOWNLOAD ERROR: {filename} - {e}")
            continue

        source_path = SOURCE_DIR / filename
        source_path.write_text(resp.text, encoding="utf-8")

        binary_path = BINARY_DIR / stem
        print(f"[GT Builder] Compiling {filename}...")
        success = compile_binary(source_path, binary_path)

        if success:
            labels[stem] = {
                "true_category": category,
                "source_file": filename,
                "binary_path": str(binary_path),
            }
            build_results.append(f"OK: {filename} -> {category}")
            print(f"[GT Builder] OK: {stem} (category={category})")
        else:
            build_results.append(f"COMPILE FAILED: {filename}")
            print(f"[GT Builder] Compile failed: {filename}")

        time.sleep(0.5)

    LABEL_FILE.write_text(json.dumps(labels, indent=2), encoding="utf-8")
    BUILD_REPORT.write_text("\n".join(build_results), encoding="utf-8")

    print(f"\n[GT Builder] Built {len(labels)} labeled binaries")
    print(f"[GT Builder] Labels: {LABEL_FILE}")
    print(f"[GT Builder] Report: {BUILD_REPORT}")
    return labels

if __name__ == "__main__":
    build_ground_truth()
