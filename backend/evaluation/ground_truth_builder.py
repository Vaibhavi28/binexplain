import os
import json
import subprocess
import shutil
import time
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "ground_truth"
BINARY_DIR = OUTPUT_DIR / "binaries"
LABEL_FILE = OUTPUT_DIR / "labels.json"
BUILD_REPORT = OUTPUT_DIR / "build_report.txt"
SOURCE_DIR = OUTPUT_DIR / "sources"
TEMP_DIR = Path(__file__).parent / "temp_how2heap"

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
    print("[GT Builder] Fetching how2heap via git clone (avoids API rate limits)...")
    if TEMP_DIR.exists():
        try:
            shutil.rmtree(TEMP_DIR)
        except Exception:
            pass
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/shellphish/how2heap.git", str(TEMP_DIR)],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"[GT Builder] Git clone failed: {result.stderr}")
            return []
        
        c_files = []
        for root, dirs, files in os.walk(TEMP_DIR):
            for fname in files:
                if fname.endswith(".c"):
                    fpath = Path(root) / fname
                    c_files.append({
                        "name": fname,
                        "local_path": fpath
                    })
        print(f"[GT Builder] Found {len(c_files)} .c files in repository")
        return c_files
    except Exception as e:
        print(f"[GT Builder] Failed to clone repo: {e}")
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
        print("[GT Builder] No files retrieved. Compilation aborted.")
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

        print(f"[GT Builder] Reading {filename}...")
        try:
            content = file_info["local_path"].read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            build_results.append(f"READ ERROR: {filename} - {e}")
            continue

        source_path = SOURCE_DIR / filename
        source_path.write_text(content, encoding="utf-8")

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

    LABEL_FILE.write_text(json.dumps(labels, indent=2), encoding="utf-8")
    BUILD_REPORT.write_text("\n".join(build_results), encoding="utf-8")

    # Cleanup local checkout
    if TEMP_DIR.exists():
        try:
            shutil.rmtree(TEMP_DIR)
        except Exception:
            pass

    print(f"\n[GT Builder] Built {len(labels)} labeled binaries")
    print(f"[GT Builder] Labels: {LABEL_FILE}")
    print(f"[GT Builder] Report: {BUILD_REPORT}")
    return labels

if __name__ == "__main__":
    build_ground_truth()
