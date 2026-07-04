import os
import sys

# Ensure backend directory is in the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from knowledge_base.scraper import (
    contains_credentials,
    calculate_writeup_quality,
    is_duplicate_content,
    WALKTHROUGHS_DIR
)

def clean_walkthroughs():
    print(f"Starting walkthrough database quality and deduplication cleanup...")
    print(f"Walkthroughs directory: {WALKTHROUGHS_DIR}")
    
    total_checked = 0
    deleted_creds = 0
    deleted_quality = 0
    deleted_dupes = 0
    updated_headers = 0
    
    # We will keep a list of files sorted by path or date so we process them consistently
    all_files = []
    for root, dirs, files in os.walk(WALKTHROUGHS_DIR):
        for fname in files:
            if fname.endswith('.txt'):
                all_files.append(os.path.join(root, fname))
                
    all_files.sort() # Consistent order
    print(f"Found {len(all_files)} total writeup files to check.")
    
    # Fingerprint kept cache in memory for fast deduplication check
    kept_fingerprints = []
    
    for fpath in all_files:
        total_checked += 1
        if not os.path.exists(fpath):
            continue
            
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {fpath}: {e}")
            continue
            
        # 1. Credential check
        if contains_credentials(content):
            print(f"[-] Deleting (credentials): {os.path.basename(fpath)}")
            os.remove(fpath)
            deleted_creds += 1
            continue
            
        # 2. Quality check
        is_quality, quality_score, quality_reason = calculate_writeup_quality(content)
        if not is_quality:
            print(f"[-] Deleting (low quality - {quality_reason}): {os.path.basename(fpath)}")
            os.remove(fpath)
            deleted_quality += 1
            continue
            
        # 3. Deduplication check
        content_fingerprint = content[:300].lower().strip()
        is_dupe = False
        if len(content_fingerprint) > 50:
            for existing_fp in kept_fingerprints:
                if len(existing_fp) > 50:
                    if content_fingerprint[:100] in existing_fp or \
                       existing_fp[:100] in content_fingerprint:
                        is_dupe = True
                        break
        
        if is_dupe:
            print(f"[-] Deleting (duplicate): {os.path.basename(fpath)}")
            os.remove(fpath)
            deleted_dupes += 1
            continue
            
        # All checks passed, keep this file and add to kept_fingerprints
        kept_fingerprints.append(content_fingerprint)
        
        # 4. Check if QUALITY_SCORE is in the header, if not, update header
        parts = content.split('---', 2)
        if len(parts) >= 3:
            header = parts[1]
            body = parts[2]
            if "QUALITY_SCORE:" not in header:
                # Add quality score to header
                header_lines = header.rstrip().split('\n')
                header_lines.append(f"QUALITY_SCORE: {quality_score:.2f}")
                new_header = '\n'.join(header_lines) + '\n'
                new_content = f"---{new_header}---{body}"
                
                try:
                    with open(fpath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    updated_headers += 1
                except Exception as e:
                    print(f"Error updating header for {fpath}: {e}")
                    
    print(f"\nCleanup Summary:")
    print(f"  Total checked:       {total_checked}")
    print(f"  Deleted (creds):     {deleted_creds}")
    print(f"  Deleted (quality):   {deleted_quality}")
    print(f"  Deleted (dupes):     {deleted_dupes}")
    print(f"  Updated headers:     {updated_headers}")
    print(f"  Remaining active:    {len(kept_fingerprints)}")

if __name__ == "__main__":
    clean_walkthroughs()
