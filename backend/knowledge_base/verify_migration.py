import os
WALKTHROUGH_DIR = 'backend/knowledge_base/walkthroughs'
KNOWN = [
    'ret2win','ret2libc','format_string','rop_chain','heap_exploitation',
    'shellcode','ret2plt','got_overwrite','ret2csu','srop','fastbin_dup',
    'tcache_poisoning','use_after_free','one_gadget','canary_bypass',
    'pie_bypass','off_by_one','stack_pivot','integer_overflow',
    'seccomp_bypass','house_of_force','house_of_spirit','house_of_orange',
    'unsorted_bin_attack','others'
]
loose = [f for f in os.listdir(WALKTHROUGH_DIR) if f.endswith('.txt')]
print('PASS: No loose files' if not loose else f'FAIL: {len(loose)} loose files')
total = 0
print(f'\n{"Category":<25} {"Files":>8}')
print('-'*35)
for cat in KNOWN:
    p = os.path.join(WALKTHROUGH_DIR, cat)
    c = len([f for f in os.listdir(p) if f.endswith('.txt')]) if os.path.isdir(p) else 0
    total += c
    print(f'{cat:<25} {c:>8}')
unexpected = [d for d in os.listdir(WALKTHROUGH_DIR)
              if os.path.isdir(os.path.join(WALKTHROUGH_DIR,d))
              and d not in KNOWN]
if unexpected: print(f'\nWARNING unexpected folders: {unexpected}')
print(f'\nTotal: {total}/5200')
