import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import is_chat_response_specific

def test_provenance_matching_5_plus_1():
    binary_context = {
        "filename": "vuln_binary",
        "ctf_category": "ret2win",
        "functions": [{"name": "win"}, {"name": "main"}, {"name": "vuln"}],
        "predicted_offset": 88,
        "protections": {"nx": "Enabled", "pie": "Disabled", "canary": "Disabled"},
        "disassembly": [{"line": "0x000011b9 <+20>: call 0x1050 <puts@plt>"}],
        "rop_gadgets": [{"gadget": "pop rdi; ret"}]
    }

    # 1. detected_function match
    resp_func = "To solve this challenge, you should target the win() function which prints the flag directly."
    is_spec, prov = is_chat_response_specific(resp_func, binary_context)
    assert is_spec is True
    assert prov["evidence_type"] == "detected_function"
    assert prov["evidence_value"] == "win"

    # 2. overflow_offset match
    resp_offset = "The buffer overflow requires an offset of 88 bytes before overwriting the saved instruction pointer."
    is_spec, prov = is_chat_response_specific(resp_offset, binary_context)
    assert is_spec is True
    assert prov["evidence_type"] == "overflow_offset"
    assert prov["evidence_value"] == "88"

    # 3. protection_flag match
    resp_prot = "Notice that the binary has NX enabled, so shellcode injection on the stack will not execute."
    is_spec, prov = is_chat_response_specific(resp_prot, binary_context)
    assert is_spec is True
    assert prov["evidence_type"] == "protection_flag"
    assert prov["evidence_value"] == "NX: Enabled"

    # 4. disassembly_line match
    resp_disasm = "Looking at the disassembly, notice line 0x000011b9 <+20>: call 0x1050 <puts@plt> where user input is output."
    is_spec, prov = is_chat_response_specific(resp_disasm, binary_context)
    assert is_spec is True
    assert prov["evidence_type"] == "disassembly_line"
    assert prov["evidence_value"] == "0x000011b9 <+20>: call 0x1050 <puts@plt>"

    # 5. rop_gadget match
    resp_rop = "You can construct a simple ROP chain by placing the pop rdi; ret gadget onto the stack to load arguments."
    is_spec, prov = is_chat_response_specific(resp_rop, binary_context)
    assert is_spec is True
    assert prov["evidence_type"] == "rop_gadget"
    assert prov["evidence_value"] == "pop rdi; ret"

    # 6. Deliberately generic response (general fallback)
    resp_generic = "Binary exploitation involves understanding memory layout, stack frames, and CPU register state."
    is_spec, prov = is_chat_response_specific(resp_generic, binary_context)
    assert prov["evidence_type"] == "general"
    assert prov["evidence_value"] is None

def test_provenance_no_false_positive_on_word_substrings():
    # Response contains 'compiled' (which has 'pie' substring), but NO actual mention of PIE or other context
    binary_context = {
        "protections": {"pie": "Disabled"},
        "functions": ["win"]
    }
    resp = "This binary was compiled with GCC on a standard Linux environment."
    _, prov = is_chat_response_specific(resp, binary_context)
    assert prov["evidence_type"] == "general"
    assert prov["evidence_value"] is None
