TECHNIQUE_TAGS = {
    "tcache_poisoning": ["tcache poison", "tcache dup", "tcache attack"],
    "fastbin_dup": ["fastbin dup", "fast bin duplicate", "double free fastbin"],
    "house_of_force": ["house of force"],
    "house_of_spirit": ["house of spirit"],
    "house_of_orange": ["house of orange"],
    "unsorted_bin_attack": ["unsorted bin attack", "unsortedbin"],
    "use_after_free": ["use after free", "use-after-free", "uaf"],
    "double_free": ["double free", "double-free"],
    "format_string_leak": ["format string leak", "%p leak", "stack leak printf"],
    "format_string_write": ["%n", "format string write", "arbitrary write printf"],
    "ret2libc": ["ret2libc", "return to libc", "return-to-libc"],
    "ret2win": ["ret2win", "win function", "ret2flag"],
    "rop_chain": ["rop chain", "return oriented programming", "gadget chain"],
    "stack_pivot": ["stack pivot", "stack migration"],
    "got_overwrite": ["got overwrite", "got hijack", "global offset table"],
    "shellcode_injection": ["shellcode injection", "shellcode execution", "nx bypass shellcode"],
    "aslr_bypass": ["aslr bypass", "address leak", "pie bypass"],
    "canary_bypass": ["canary bypass", "stack canary leak", "stack smashing protector bypass"],
    "one_gadget": ["one_gadget", "one gadget", "onegadget"],
    "seccomp_bypass": ["seccomp", "syscall filter bypass"],
    "integer_overflow": ["integer overflow", "signed unsigned"],
}

def extract_technique_tags(text: str) -> list:
    text_lower = text.lower()
    found_tags = []
    for tag, keywords in TECHNIQUE_TAGS.items():
        if any(kw in text_lower for kw in keywords):
            found_tags.append(tag)
    return found_tags
