import os
import sys
import tempfile
import pytest

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from knowledge_base.scraper import (
    contains_credentials,
    calculate_writeup_quality,
    is_duplicate_content
)

def test_contains_credentials():
    clean_text = "This is a clean writeup text for CTF."
    creds_text = "My AWS secret: aws_secret_access_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD"
    
    assert not contains_credentials(clean_text)
    assert contains_credentials(creds_text)

def test_calculate_writeup_quality():
    # Too short
    short_text = "ROP exploit ret2libc format string malloc free"
    is_q, score, reason = calculate_writeup_quality(short_text)
    assert not is_q
    assert "Too short" in reason
    assert score == 0.0

    # Long but low quality (no signals)
    long_low_text = " ".join(["hello world"] * 200)
    is_q, score, reason = calculate_writeup_quality(long_low_text)
    assert not is_q
    assert score < 0.20

    # High quality (contains signals and is long enough — >300 words)
    high_quality_text = (
        " ".join(["exploit"] * 20) + " " +
        " ".join(["pwntools"] * 20) + " " +
        " ".join(["rop"] * 20) + " " +
        " ".join(["gdb"] * 20) + " " +
        " ".join(["payload"] * 20) + " " +
        " ".join(["p64(0x400500)"] * 210)
    )

    is_q, score, reason = calculate_writeup_quality(high_quality_text)
    assert is_q
    assert score >= 0.25


def test_is_duplicate_content():
    with tempfile.TemporaryDirectory() as tmpdir:
        content1 = "---" + "\n" * 10 + "This is a unique writeup content that will be stored in a file."
        content2 = "---" + "\n" * 10 + "This is a unique writeup content that will be stored in a file. Extra stuff."
        content3 = "---" + "\n" * 10 + "Completely different text here for another writeup."

        # Write content1 to a file in tmpdir
        fpath = os.path.join(tmpdir, "writeup1.txt")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(content1)

        # Check duplicate
        assert is_duplicate_content(content2, tmpdir)
        assert not is_duplicate_content(content3, tmpdir)
