"""
Moves all existing walkthrough .txt files into category-based subfolders.
Files not matching a known category go into others/.
"""
import os, re, shutil

WALKTHROUGH_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "walkthroughs"
)

KNOWN_CATEGORIES = [
    "ret2win", "ret2libc", "format_string", "rop_chain",
    "heap_exploitation", "shellcode", "ret2plt", "got_overwrite",
    "ret2csu", "srop", "fastbin_dup", "tcache_poisoning",
    "use_after_free", "one_gadget", "canary_bypass", "pie_bypass",
    "off_by_one", "stack_pivot", "integer_overflow", "seccomp_bypass",
    "house_of_force", "house_of_spirit", "house_of_orange",
    "unsorted_bin_attack", "others"
]

def get_category_from_header(filepath: str) -> str:
    try:
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            header = f.read(500)
        match = re.search(r'CATEGORY:\s*(\S+)', header)
        if match:
            cat = match.group(1).lower().strip()
            return cat if cat in KNOWN_CATEGORIES else 'others'
        return 'others'
    except Exception:
        return 'others'

def migrate():
    all_files = []
    for root, dirs, files in os.walk(WALKTHROUGH_DIR):
        for fname in files:
            if fname.endswith('.txt'):
                all_files.append(os.path.join(root, fname))

    print(f"Found {len(all_files)} files to migrate")
    moved = {}
    skipped = 0
    errors = []

    for fpath in all_files:
        category = get_category_from_header(fpath)
        cat_dir = os.path.join(WALKTHROUGH_DIR, category)
        os.makedirs(cat_dir, exist_ok=True)
        dest = os.path.join(cat_dir, os.path.basename(fpath))

        if os.path.abspath(fpath) == os.path.abspath(dest):
            skipped += 1
            continue
        if os.path.exists(dest):
            os.remove(fpath)
            skipped += 1
            continue
        try:
            shutil.move(fpath, dest)
            moved[category] = moved.get(category, 0) + 1
        except Exception as e:
            errors.append(f"{fpath}: {e}")

    # Remove empty dirs
    for root, dirs, files in os.walk(WALKTHROUGH_DIR, topdown=False):
        for d in dirs:
            dpath = os.path.join(root, d)
            try:
                if len(os.listdir(dpath)) == 0:
                    os.rmdir(dpath)
                    print(f"Removed empty dir: {dpath}")
            except Exception:
                pass

    print("\n=== Migration Complete ===")
    print(f"{'Category':<25} {'Moved':>8}")
    print("-" * 35)
    for cat in sorted(moved):
        print(f"{cat:<25} {moved[cat]:>8}")
    print(f"\nTotal moved:   {sum(moved.values())}")
    print(f"Skipped/dedup: {skipped}")
    if errors:
        print(f"\nErrors: {len(errors)}")
        for e in errors: print(f"  {e}")

if __name__ == "__main__":
    migrate()
