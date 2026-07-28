# BinExplain Technical Glossary: Binary Exploitation Archetypes, Sub-Techniques, and Security Mitigations

## Document Overview and Purpose

This document serves as the formal technical glossary for BinExplain, a binary analysis and security education framework. BinExplain classifies binary exploitation challenges into six primary archetypes (`ret2win`, `ret2libc`, `format_string`, `heap_exploitation`, `rop_chain`, and `shellcode`) and maps secondary features across 21 sub-technique tags using a hybrid Retrieval-Augmented Generation (RAG) system. This glossary establishes rigorous definitions, cryptographic/architectural prerequisites, Common Weakness Enumeration (CWE) mappings, taxonomy classifications, and academic literature citations for all terms used within the BinExplain platform and its corresponding research paper. This reference uses the exact archetype vocabulary as the BinExplain paper and is intended for use in academic peer review, security education research, and vulnerability taxonomy verification.

## How to Use This Glossary

The terminology defined herein corresponds directly to strings generated in BinExplain's automated classification output. 

- **BinExplain Labels:** Rendered in `monospace` font, these represent the exact programmatic identifiers used by BinExplain's classifier and hybrid RAG indexing system.
- **Alternative Names and Synonyms:** Documents nomenclature used across competitive Capture-The-Flag (CTF) platforms (e.g., CTFtime, HackTheBox, pwn.college), security analysis tooling (e.g., pwntools, checksec, GDB/GEF), and peer-reviewed academic literature.
- **Taxonomic Classification:** Positions each technique within the broader hierarchy of software vulnerability analysis and memory corruption theory.
- **Core Conditions:** Specifies the necessary memory layout properties, compiler security settings, and attacker-controlled primitives required to execute each technique successfully.
- **CWE Mappings:** Formally maps techniques to MITRE Common Weakness Enumeration standard identifiers.
- **Citations:** Formatted in ACM author-year style, linking entries to foundational security research, authoritative community guides, and official weakness/mitigation databases.

---

## Section A: Primary Archetypes

### ret2win: Return-to-Win

**BinExplain classification label:** `ret2win`

**Full name:** Return-to-Win

**Alternative names and synonyms:**
- ret2flag (widely used across pwn.college and beginner CTF platforms)
- Win function exploitation (common on CTFtime writeups and HackTheBox)
- Hidden function execution (frequently referenced in security education literature)
- Backdoor function exploitation (used in academic introductory vulnerability assessment courses)
- Privileged function redirection via control-flow hijacking (formal academic equivalent)

**Classification:**
Return-to-Win (`ret2win`) is the fundamental baseline class of control-flow hijacking via stack-based buffer overflow. Taxonomically, it sits as a sub-type of return address overwrite attacks under the broader umbrella of memory safety violation exploits. It represents the simplest form of code reuse, wherein execution is redirected to existing executable logic within the target binary's address space without requiring parameter synthesis or multi-gadget chaining.

**Core conditions:**
- **Required Vulnerability:** A stack-based buffer overflow (or direct memory corruption primitive) allowing unbounded write access past the stack frame's saved instruction pointer (`saved RIP/EIP`).
- **Required Binary Property:** The binary must contain an existing, uncalled function (typically designated `win`, `flag`, `shell`, `backdoor`, `get_flag`, or `print_flag`) containing instructions that emit the flag or grant elevated privileges.
- **Required Protections State:** Stack Canaries must be absent (or leaked/bypassed); No-Execute (`NX`) status does not block execution because the target function resides within a pre-existing executable segment (`.text`).
- **Required Attacker Knowledge:** The exact byte offset from the target buffer to the saved return address on the stack, and the static or runtime base address of the target win function.

**CWE mapping:**
- **Primary:** CWE-121: Stack-based Buffer Overflow
- **Secondary:** CWE-691: Insufficient Control Flow Management

**Relationship to other archetypes:**
`ret2win` is a prerequisite gateway archetype. Learners and automated classifiers evaluate `ret2win` to confirm basic control-flow control. Binaries presenting `ret2win` conditions typically transform into `ret2libc` or `rop_chain` archetypes if the intended target function is removed or modified to require specific runtime arguments.

**Sources:**
1. ir0nstone. 2022. ret2win - Binary Exploitation. *ir0nstone's Security Notes*. Retrieved July 28, 2026 from https://ir0nstone.gitbook.io/notes/types/stack/ret2win
2. Guyinatuxedo. 2020. ret2win - Nightmare CTF Tutorials. *Nightmare*. Retrieved July 28, 2026 from https://guyinatuxedo.github.io/04-bof_variable/index.html
3. MITRE. 2023. CWE-121: Stack-based Buffer Overflow. *Common Weakness Enumeration*. Retrieved July 28, 2026 from https://cwe.mitre.org/data/definitions/121.html

---

### ret2libc: Return-to-libc

**BinExplain classification label:** `ret2libc`

**Full name:** Return-to-libc

**Alternative names and synonyms:**
- Return-to-library (formal academic literature)
- ret2system (commonly used on CTFtime and StackExchange when targeting `system()`)
- Return-to-function / ret2plt (frequently used in pwntools and CTF writeups targeting PLT entries)
- Borrowed code chunk attack (historical precursor term in security literature)

> **Note:** The security community recognizes `ret2libc` as both a standalone exploitation technique and the foundational subset of Return-Oriented Programming (ROP). Traditional `ret2libc` transfers control to the entry point of a complete C standard library function (such as `system()` or `execve()`), whereas generalized ROP chains multiple short instruction sequences ending in `ret`. BinExplain categorizes single-function library invocation as `ret2libc` and multi-gadget arbitrary sequence execution as `rop_chain`.

**Classification:**
`ret2libc` is a specialized control-flow hijacking technique belonging to the code reuse family. Taxonomically, it acts as a bridge between simple return address overwrites (`ret2win`) and generalized Return-Oriented Programming (`rop_chain`). It replaces direct shellcode execution with execution of pre-existing C library routines already mapped into the process memory space.

**Core conditions:**
- **Required Vulnerability:** Stack-based buffer overflow or control-flow hijack primitive (e.g., function pointer overwrite).
- **Required Binary Property:** C standard library (`libc.so.6` or equivalent) dynamically or statically linked and mapped with execute permissions.
- **Required Protections State:** Effective against No-Execute (`NX`) enabled binaries; requires Address Space Layout Randomization (`ASLR`) to be either disabled or bypassed via an information disclosure (memory leak).
- **Required Attacker Knowledge:** Base address of `libc` in the process address space, symbol offsets for target functions (e.g., `system()`), memory address of string arguments (e.g., `"/bin/sh"`), and applicable calling convention rules (e.g., setting `RDI` in x86_64).

**CWE mapping:**
- **Primary:** CWE-121: Stack-based Buffer Overflow
- **Secondary:** CWE-243: Creation of chroot Jail Without Changing Working Directory

**Relationship to other archetypes:**
`ret2libc` succeeds `ret2win` in complexity when binaries lack dedicated win functions. It directly informs `rop_chain` execution: when passing parameters to library functions under 64-bit calling conventions, attackers must construct minimal ROP chains (e.g., `pop rdi; ret`) to populate register arguments prior to invoking `ret2libc`.

**Sources:**
1. Shacham, H. 2007. The geometry of innocent flesh on the bone: Return-into-libc without function calls (on the x86). In *Proceedings of the 14th ACM Conference on Computer and Communications Security (CCS '07)*. ACM, New York, NY, USA, 552–561. https://doi.org/10.1145/1315245.1315313
2. ir0nstone. 2022. ret2libc - Binary Exploitation. *ir0nstone's Security Notes*. Retrieved July 28, 2026 from https://ir0nstone.gitbook.io/notes/types/stack/return-to-libc
3. pwn.college. 2023. Return-to-libc and Code Reuse. *pwn.college Security Modules*. Retrieved July 28, 2026 from https://pwn.college/program-security/return-oriented-programming/

---

### format_string: Format String Attack

**BinExplain classification label:** `format_string`

**Full name:** Format String Attack (also: Format String Vulnerability Exploitation)

**Alternative names and synonyms:**
- fmt string (ubiquitous shorthand on CTFtime, HackTheBox, and Discord channels)
- printf exploitation (common term in security training materials)
- Format string bug exploitation (academic literature focus)
- Uncontrolled format string (official OWASP classification title)
- User-controlled format string vulnerability (MITRE CWE nomenclature)

> **Note:** A critical distinction exists between the underlying software flaw and the exploitation technique. The flaw is an "uncontrolled format string vulnerability" (`CWE-134`). The technique is a "format string attack," which leverages format specifiers (e.g., `%x`, `%s`, `%p`, `%n`, `$hn`, `$Nn`) to achieve arbitrary stack reading or arbitrary memory writing.

**Classification:**
Format String Attack belongs to the input validation failure and variadic argument specification exploitation classes. Unlike stack overflow archetypes that exploit missing memory boundary checks during data copy operations, format string attacks exploit semantic misinterpretation of variadic argument conventions in C standard library functions (`printf`, `sprintf`, `fprintf`, `snprintf`, `syslog`).

**Core conditions:**
- **Required Vulnerability:** Direct evaluation of user-supplied buffer data as the format string argument (e.g., `printf(buffer)` instead of `printf("%s", buffer)`).
- **Required Binary Property:** Access to standard format output or logging routines accepting variadic parameters.
- **Required Protections State:** Independent of No-Execute (`NX`) and Position Independent Executable (`PIE`); format string read/write primitives function regardless of execution protections, though RELRO status determines whether Global Offset Table (`GOT`) entries are writable targets.
- **Required Attacker Knowledge:** Distance (in stack argument positions) from the format function stack frame to the user-controlled input buffer; target memory addresses for reading or overwriting.

**CWE mapping:**
- **Primary:** CWE-134: Use of Externally-Controlled Format String

**Relationship to other archetypes:**
Format string attacks frequently act as enablers for other archetypes. Attackers utilize format string read primitives (`%p`, `%s`) to leak Stack Canaries (enabling `ret2win` or `ret2libc`) or process/library addresses (bypassing ASLR/PIE). They utilize format string write primitives (`%n`) to overwrite Global Offset Table (`GOT`) entries or return addresses, converting format string flaws into direct control-flow hijacking.

**Sources:**
1. OWASP. 2021. Format String Bug. *OWASP Foundation Vulnerability Documentation*. Retrieved July 28, 2026 from https://owasp.org/www-community/vulnerabilities/Format_string_bug
2. Newsham, T. 2000. Format String Attacks. *Guardent, Inc. Technical Report*. Retrieved July 28, 2026 from https://cgisecurity.com/lib/formatstring-1.2.pdf
3. MITRE. 2023. CWE-134: Use of Externally-Controlled Format String. *Common Weakness Enumeration*. Retrieved July 28, 2026 from https://cwe.mitre.org/data/definitions/134.html

---

### heap_exploitation: Heap Exploitation

**BinExplain classification label:** `heap_exploitation`

**Full name:** Heap Exploitation

**Alternative names and synonyms:**
- Dynamic memory exploitation (formal software engineering and academic security terminology)
- Allocator exploitation (used in operating system and compiler research)
- glibc heap exploitation / ptmalloc exploitation (specific to Linux target environments)
- Heap memory corruption (broad MITRE vulnerability category)

> **Note:** "Heap exploitation" is an overarching archetype identifier encompassing multiple distinct sub-techniques (such as `tcache_poisoning`, `fastbin_dup`, `house_of_force`, and `use_after_free`). BinExplain classifies macro heap state manipulation under `heap_exploitation` while attributing precise mechanics via Section B sub-technique tags.

**Classification:**
Heap Exploitation is an umbrella archetype covering attacks that manipulate the internal meta-structures, chunk headers, and free-list bins of dynamic memory allocators (predominantly `glibc`'s `ptmalloc2` allocator on modern Linux systems). Its objective is corrupting allocator metadata to force allocation of arbitrary memory locations or gain arbitrary write primitives.

**Core conditions:**
- **Required Vulnerability:** A heap-level memory safety defect, such as Use-After-Free (`UAF`), Double Free, Heap-based Buffer Overflow, or Off-by-One/Off-by-Null allocation metadata corruption.
- **Required Binary Property:** Dynamic memory allocation routines (`malloc`, `calloc`, `realloc`, `free`) managing heap state based on user actions.
- **Required Protections State:** Dependent on allocator enforcement checks present in specific target `glibc` runtime versions (e.g., `tcache` introduced in `glibc 2.26`, safe-linking pointers introduced in `glibc 2.32`).
- **Required Attacker Knowledge:** Relative arrangement of heap chunks, heap base address (if ASLR/PIE active), target allocator version details, and target overwrite addresses (e.g., `__free_hook`, `__malloc_hook`, or stack pointers).

**CWE mapping:**
- **Primary:** CWE-122: Heap-based Buffer Overflow
- **Secondary:** CWE-416: Use After Free; CWE-415: Double Free

**Relationship to other archetypes:**
Heap exploitation techniques rarely achieve direct execution independently; instead, they generate arbitrary read/write primitives. These primitives are subsequently leveraged to overwrite function pointers, stack frames, or GOT entries, resolving into `ret2libc` or `rop_chain` execution flows.

**Sources:**
1. Shellphish. 2023. how2heap: A repository for learning heap exploitation. *GitHub Security Repository*. Retrieved July 28, 2026 from https://github.com/shellphish/how2heap
2. Kaempf, M. 2001. Vudo - An object-oriented approach to malloc() exploitation. *Phrack Magazine*, Vol. 11, Issue 57. Retrieved July 28, 2026 from http://phrack.org/issues/57/8.html
3. MITRE. 2023. CWE-122: Heap-based Buffer Overflow. *Common Weakness Enumeration*. Retrieved July 28, 2026 from https://cwe.mitre.org/data/definitions/122.html

---

### rop_chain: Return-Oriented Programming (ROP Chain)

**BinExplain classification label:** `rop_chain`

**Full name:** Return-Oriented Programming (ROP Chain)

**Alternative names and synonyms:**
- ROP (standard industry and academic acronym)
- Gadget chaining (descriptive term in reverse engineering tools)
- Code reuse attack (broad theoretical taxonomy classification)
- Return-oriented exploitation (academic literature reference)
- Borrowed code chunks attack (original term introduced by Buchanan et al., 2008)

> **Note:** Jump-Oriented Programming (`JOP`) and Call-Oriented Programming (`COP`) are closely related code-reuse variants that substitute `jmp` or `call` instructions for `ret` as gadget terminators. BinExplain includes JOP/COP variants within the general `rop_chain` structural archetype classification.

**Classification:**
Return-Oriented Programming is an advanced code reuse paradigm. It is the generalized generalization of `ret2libc`. ROP has been proven to be Turing-complete in most non-trivial binary address spaces: an attacker possessing sufficient instruction gadgets can execute arbitrary computations and system invocations without injecting any executable machine code.

**Core conditions:**
- **Required Vulnerability:** Stack buffer overflow or register/stack-pointer control primitive allowing control of the instruction pointer (`RIP`) and stack pointer (`RSP`).
- **Required Binary Property:** Presence of executable code segments containing instruction sequences ending in return instructions (`ret` / `0xc3`), known as "gadgets".
- **Required Protections State:** Designed explicitly to bypass No-Execute (`NX` / `DEP`). If `ASLR` or `PIE` is enabled, an address leak is mandatory to compute gadget runtime locations.
- **Required Attacker Knowledge:** Addresses of required gadgets (e.g., `pop rdi; ret`, `pop rsi; pop rdx; ret`, `syscall`), layout of system call conventions, and valid stack alignment (e.g., 16-byte alignment requirement for x86_64 `movaps` instructions).

**CWE mapping:**
- **Primary:** CWE-693: Protection Mechanism Failure
- **Secondary:** CWE-121: Stack-based Buffer Overflow

**Relationship to other archetypes:**
`ret2libc` represents a single-step ROP sequence. `rop_chain` generalizes this mechanism into arbitrary multi-step execution. When binaries restrict direct function parameters or require complex syscall setup (e.g., invoking `mprotect` to disable NX), `rop_chain` provides the necessary mechanism.

**Sources:**
1. Buchanan, E., Roemer, R., Shacham, H., and Savage, S. 2008. When good instructions go bad: Generalizing return-oriented programming to RISC. In *Proceedings of the 15th ACM Conference on Computer and Communications Security (CCS '08)*. ACM, New York, NY, USA, 27–38. https://doi.org/10.1145/1455770.1455776
2. Roemer, R., Buchanan, E., Shacham, H., and Savage, S. 2012. Return-oriented programming: Systems, languages, and applications. *ACM Transactions on Information and System Security (TISSEC)* 15, 1 (2012), 2:1–2:34. https://doi.org/10.1145/2133375.2133377
3. ir0nstone. 2022. Return Oriented Programming - ROP. *ir0nstone's Security Notes*. Retrieved July 28, 2026 from https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming

---

### shellcode: Shellcode Injection

**BinExplain classification label:** `shellcode`

**Full name:** Shellcode Injection

**Alternative names and synonyms:**
- Code injection (broad MITRE and academic categorization)
- Shellcode execution (common term across CTF platforms and penetration testing literature)
- Stack shellcode injection (specific variant targeting stack-allocated buffers)
- Arbitrary machine code injection (formal computer security specification)

> **Note:** Historically, "shellcode" designated machine code specifically compiled to spawn a command shell (e.g., `/bin/sh`). In modern CTF environments and BinExplain taxonomy, it denotes any attacker-injected machine code payload placed into memory for direct instruction execution.

**Classification:**
Shellcode Injection is the baseline direct code injection archetype. It represents the historically foundational vulnerability class in systems security, where arbitrary attacker data is executed directly by the CPU instruction pointer.

**Core conditions:**
- **Required Vulnerability:** Memory corruption flaw permitting data write access to a writable memory region, coupled with control-flow redirection to that region.
- **Required Binary Property:** Memory segment configured with simultaneous Write and Execute (`WX`) permissions (or absent `NX` enforcement).
- **Required Protections State:** No-Execute (`NX` / `DEP`) must be disabled (or explicitly neutralized via `mprotect`). If ASLR is enabled, stack/heap pointer locations must be leaked or predicted via NOP sleds.
- **Required Attacker Knowledge:** Location of the injected buffer in memory, and restrictions on payload byte values (e.g., avoiding `0x00` in string functions or `0x0a` in line reads).

**CWE mapping:**
- **Primary:** CWE-94: Improper Control of Generation of Code ("Code Injection")
- **Secondary:** CWE-121: Stack-based Buffer Overflow

**Relationship to other archetypes:**
Shellcode injection is the historical predecessor of all modern memory corruption archetypes. The introduction of hardware-enforced No-Execute (`NX`) bits rendered direct shellcode execution infeasible on modern systems, directly driving the development of code reuse techniques (`ret2libc`, `rop_chain`).

**Sources:**
1. One, A. 1996. Smashing The Stack For Fun And Profit. *Phrack Magazine*, Vol. 7, Issue 49. Retrieved July 28, 2026 from http://phrack.org/issues/49/14.html
2. Foster, J.C., Price, M., Soderlund, C., and Beaver, N. 2005. *Buffer Overflow Attacks: Detect, Exploit, Prevent*. Syngress Publishing. ISBN: 978-1597490221.
3. MITRE. 2023. CWE-94: Improper Control of Generation of Code. *Common Weakness Enumeration*. Retrieved July 28, 2026 from https://cwe.mitre.org/data/definitions/94.html

---

## Section B: Sub-Technique Tags

### tcache_poisoning

**Full name:** Thread Local Cache (tcache) Poisoning

**Alternative names:** tcache bin corruption, tcache arbitrary allocation

**Classification:** Sub-technique of glibc heap exploitation targeting post-2.26 thread local storage caching allocations.

**Core condition:** Corrupting the forward (`next`) pointer of a freed tcache chunk to return an arbitrary memory address on subsequent `malloc()` calls.

**CWE mapping:** CWE-122: Heap-based Buffer Overflow

**Sources:**
1. Shellphish. 2023. how2heap: tcache_poisoning. *GitHub Security Repository*. https://github.com/shellphish/how2heap
2. ir0nstone. 2022. Heap - Tcache Poisoning. *ir0nstone Notes*. https://ir0nstone.gitbook.io/notes/types/heap/tcache-poisoning

---

### fastbin_dup

**Full name:** Fastbin Double Free / Fastbin Duplication

**Alternative names:** fastbin double free, fastbin poisoning

**Classification:** Sub-technique of glibc heap exploitation manipulating fastbin single-linked lists.

**Core condition:** Freeing an active fastbin chunk twice (with an intervening allocation) to bypass double-free sanity checks and duplicate chunk allocations.

**CWE mapping:** CWE-415: Double Free

**Sources:**
1. Shellphish. 2023. how2heap: fastbin_dup. *GitHub Security Repository*. https://github.com/shellphish/how2heap
2. Guyinatuxedo. 2020. Fastbin Dup - Nightmare Tutorials. *Nightmare*. https://guyinatuxedo.github.io/

---

### house_of_force

**Full name:** The House of Force

**Alternative names:** Wilderness chunk corruption, Top chunk size overwrite

**Classification:** Sub-technique of glibc heap exploitation manipulating the heap top (wilderness) chunk size field.

**Core condition:** Overwriting the wilderness chunk size to a near-infinite value (`-1`), enabling arbitrary memory allocation via wrapping offsets.

**CWE mapping:** CWE-122: Heap-based Buffer Overflow

**Sources:**
1. Shellphish. 2023. how2heap: house_of_force. *GitHub Security Repository*. https://github.com/shellphish/how2heap
2. BlackNg. 2016. House of Force Attack. *CTF Paper Series*. https://ctftime.org

---

### house_of_spirit

**Full name:** The House of Spirit

**Alternative names:** Fake chunk free, House of Spirit allocation

**Classification:** Sub-technique of glibc heap exploitation involving fake chunk injection into fastbins or tcache.

**Core condition:** Crafting a valid fake chunk header on the stack or in data segments and passing its address to `free()`.

**CWE mapping:** CWE-122: Heap-based Buffer Overflow

**Sources:**
1. Shellphish. 2023. how2heap: house_of_spirit. *GitHub Security Repository*. https://github.com/shellphish/how2heap
2. ir0nstone. 2022. House of Spirit - Heap. *ir0nstone Notes*. https://ir0nstone.gitbook.io

---

### house_of_orange

**Full name:** The House of Orange

**Alternative names:** Top chunk abort exploitation, `_IO_FILE` heap exploitation without free

**Classification:** Advanced sub-technique of glibc heap exploitation utilizing `malloc_printerr` and `_IO_FILE` structure corruption.

**Core condition:** Corrupting the top chunk size to force reallocation via `sysmalloc`, placing old top chunks into unsorted bins without direct `free()` calls.

**CWE mapping:** CWE-122: Heap-based Buffer Overflow

**Sources:**
1. Shellphish. 2023. how2heap: house_of_orange. *GitHub Security Repository*. https://github.com/shellphish/how2heap
2. 4b5F. 2018. House of Orange Detailed Walkthrough. *Phrack / Security Research*. https://ctftime.org

---

### unsorted_bin_attack

**Full name:** Unsorted Bin Attack

**Alternative names:** Unsorted bin write primitive, Unsorted bin list corruption

**Classification:** Sub-technique of glibc heap exploitation manipulating doubly-linked unsorted bin list pointers.

**Core condition:** Overwriting the back (`bk`) pointer of an unsorted bin chunk to write a large library address pointer to an arbitrary target location.

**CWE mapping:** CWE-122: Heap-based Buffer Overflow

**Sources:**
1. Shellphish. 2023. how2heap: unsorted_bin_attack. *GitHub Security Repository*. https://github.com/shellphish/how2heap
2. Guyinatuxedo. 2020. Unsorted Bin Attack - Nightmare. *Nightmare*. https://guyinatuxedo.github.io/

---

### use_after_free

**Full name:** Use-After-Free (UAF)

**Alternative names:** UAF read/write, Stale pointer dereference

**Classification:** Dynamic memory management bug primitive enabling sub-techniques across heap exploitation.

**Core condition:** Accessing or modifying a memory region via a pointer that remains active after the underlying allocation has been freed.

**CWE mapping:** CWE-416: Use After Free

**Sources:**
1. MITRE. 2023. CWE-416: Use After Free. *CWE Database*. https://cwe.mitre.org/data/definitions/416.html
2. OWASP. 2022. Using Freed Memory Vulnerability. *OWASP*. https://owasp.org

---

### double_free

**Full name:** Double Free Vulnerability

**Alternative names:** Deallocation duplication, Unsafe double free

**Classification:** Dynamic memory management flaw primitive utilized in heap bin poisoning.

**Core condition:** Calling `free()` twice on the exact same pointer reference without an intervening allocation step.

**CWE mapping:** CWE-415: Double Free

**Sources:**
1. MITRE. 2023. CWE-415: Double Free. *CWE Database*. https://cwe.mitre.org/data/definitions/415.html
2. pwn.college. 2023. Heap Exploitation Basics. *pwn.college*. https://pwn.college

---

### format_string_leak

**Full name:** Format String Information Disclosure (Leak)

**Alternative names:** Stack reading via format strings, Arbitrary memory inspection

**Classification:** Sub-technique of format string exploitation specialized for memory layout extraction.

**Core condition:** Executing format specifiers (`%p`, `%x`, `%s`) over user-controlled format strings to inspect stack frames and leaked pointers.

**CWE mapping:** CWE-134: Use of Externally-Controlled Format String

**Sources:**
1. ir0nstone. 2022. Format String Leaks. *ir0nstone Notes*. https://ir0nstone.gitbook.io
2. OWASP. 2021. Format String Bug. *OWASP*. https://owasp.org

---

### format_string_write

**Full name:** Format String Arbitrary Write

**Alternative names:** Pointer overwrite via `%n`, Format string write primitive

**Classification:** Sub-technique of format string exploitation specialized for memory modification.

**Core condition:** Employing `%n`, `%hn`, or `%hhn` specifiers to write the cumulative printed character count into arbitrary target memory addresses.

**CWE mapping:** CWE-134: Use of Externally-Controlled Format String

**Sources:**
1. ir0nstone. 2022. Format String Writes. *ir0nstone Notes*. https://ir0nstone.gitbook.io
2. Guyinatuxedo. 2020. Format String Writes - Nightmare. *Nightmare*. https://guyinatuxedo.github.io/

---

### ret2libc

**Full name:** Return-to-libc (Sub-Technique Tag)

**Alternative names:** Library call redirection, Function call reuse

**Classification:** Sub-technique tag identifying single library function invocation primitives within BinExplain.

**Core condition:** Overwriting control flow to execute a standard C library entry point with controlled stack or register arguments.

**CWE mapping:** CWE-121: Stack-based Buffer Overflow

**Sources:**
1. Shacham, H. 2007. The geometry of innocent flesh on the bone. *CCS '07*. https://doi.org/10.1145/1315245.1315313
2. ir0nstone. 2022. ret2libc. *ir0nstone Notes*. https://ir0nstone.gitbook.io

---

### ret2win

**Full name:** Return-to-Win (Sub-Technique Tag)

**Alternative names:** Win function redirection, Flag function execution

**Classification:** Sub-technique tag identifying target binary internal victory functions within BinExplain.

**Core condition:** Redirecting execution directly to an uncalled binary function that outputs target flags or spawns elevated shells.

**CWE mapping:** CWE-121: Stack-based Buffer Overflow

**Sources:**
1. ir0nstone. 2022. ret2win. *ir0nstone Notes*. https://ir0nstone.gitbook.io
2. Guyinatuxedo. 2020. ret2win. *Nightmare*. https://guyinatuxedo.github.io/

---

### rop_chain

**Full name:** Return-Oriented Programming Chain (Sub-Technique Tag)

**Alternative names:** Gadget sequence, ROP payload construction

**Classification:** Sub-technique tag denoting multi-gadget code reuse chains within BinExplain.

**Core condition:** Constructing a sequence of return-terminated instructions on the stack to achieve arbitrary computational or system call workflows.

**CWE mapping:** CWE-693: Protection Mechanism Failure

**Sources:**
1. Buchanan, E. et al. 2008. When good instructions go bad. *CCS '08*. https://doi.org/10.1145/1455770.1455776
2. Roemer, R. et al. 2012. Return-oriented programming. *TISSEC*. https://doi.org/10.1145/2133375.2133377

---

### stack_pivot

**Full name:** Stack Pivoting

**Alternative names:** Fake stack redirection, Stack pointer hijacking (`rsp`/`esp` swap)

**Classification:** Control-flow manipulation sub-technique designed to relocate the stack pointer to attacker-controlled memory regions.

**Core condition:** Modifying the stack pointer register (`RSP`/`ESP`) via gadgets like `xchg eax, esp` or `leave; ret` to execute ROP chains stored in non-stack memory.

**CWE mapping:** CWE-691: Insufficient Control Flow Management

**Sources:**
1. ir0nstone. 2022. Stack Pivoting. *ir0nstone Notes*. https://ir0nstone.gitbook.io
2. Guyinatuxedo. 2020. Stack Pivot - Nightmare. *Nightmare*. https://guyinatuxedo.github.io/

---

### got_overwrite

**Full name:** Global Offset Table (GOT) Overwrite

**Alternative names:** GOT poisoning, Dynamic linker redirection

**Classification:** Target redirection sub-technique leveraging writable dynamic resolution structures in ELF binaries.

**Core condition:** Overwriting the function pointer entry of a resolved library symbol in the `.got.plt` section with an arbitrary execution address.

**CWE mapping:** CWE-123: Write-what-where Condition

**Sources:**
1. ir0nstone. 2022. GOT Overwrite. *ir0nstone Notes*. https://ir0nstone.gitbook.io
2. pwn.college. 2023. Dynamic Linking and the GOT. *pwn.college*. https://pwn.college

---

### shellcode_injection

**Full name:** Shellcode Injection (Sub-Technique Tag)

**Alternative names:** Raw byte payload injection, Executable buffer payload

**Classification:** Sub-technique tag denoting direct machine code execution in BinExplain analysis output.

**Core condition:** Placing executable assembly machine instructions into memory and jumping to their start address under `NX` disabled environments.

**CWE mapping:** CWE-94: Improper Control of Generation of Code

**Sources:**
1. One, A. 1996. Smashing The Stack. *Phrack*. http://phrack.org/issues/49/14.html
2. MITRE. 2023. CWE-94. *CWE Database*. https://cwe.mitre.org/data/definitions/94.html

---

### aslr_bypass

**Full name:** Address Space Layout Randomization (ASLR) Bypass

**Alternative names:** Memory leak exploitation, Information disclosure bypass

**Classification:** Security control evasion sub-technique for neutralizing process memory randomization.

**Core condition:** Deriving base addresses of executable images or shared libraries by leaking runtime pointers and computing known static offsets.

**CWE mapping:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

**Sources:**
1. Shacham, H. et al. 2004. On the effectiveness of address-space randomization. *CCS '04*. https://doi.org/10.1145/1030083.1030124
2. ir0nstone. 2022. Bypassing ASLR. *ir0nstone Notes*. https://ir0nstone.gitbook.io

---

### canary_bypass

**Full name:** Stack Canary Bypass

**Alternative names:** Stack cookie bypass, Canary leak / Canary brute-force

**Classification:** Security control evasion sub-technique neutralizing stack smashing protection.

**Core condition:** Reading stack canary secret values via format string/out-of-bounds read flaws or overwriting them with identical values during process fork exploitation.

**CWE mapping:** CWE-693: Protection Mechanism Failure

**Sources:**
1. Cowan, C. et al. 1998. StackGuard: Automatic adaptive detection and prevention of buffer-overflow attacks. *USENIX Security '98*.
2. ir0nstone. 2022. Stack Canaries. *ir0nstone Notes*. https://ir0nstone.gitbook.io

---

### one_gadget

**Full name:** One-Gadget RCE (also: Magic Gadget)

**Alternative names:** one_gadget execution, libc single-instruction shell

**Classification:** Advanced specialized sub-technique of `ret2libc` code reuse attacks.

**Core condition:** Executing a single specific instruction sequence within `libc.so.6` that directly invokes `execve("/bin/sh", NULL, NULL)` when register constraints are satisfied.

**CWE mapping:** CWE-693: Protection Mechanism Failure

**Sources:**
1. david942j. 2016. one_gadget: Tool for finding one gadget RCE in libc. *GitHub Repository*. https://github.com/david942j/one_gadget
2. Guyinatuxedo. 2020. One Gadget - Nightmare. *Nightmare Tutorials*. https://guyinatuxedo.github.io/

---

### seccomp_bypass

**Full name:** Secure Computing Mode (seccomp) Filter Bypass

**Alternative names:** Syscall filter evasion, SROP / 32-bit syscall transition bypass

**Classification:** Operating system sandbox evasion sub-technique overriding kernel system call filtering.

**Core condition:** Circumventing Linux `seccomp-bpf` syscall restrictions by exploiting allowed alternative syscalls (e.g., `openat` instead of `open`), switching execution modes (32-bit vs 64-bit ABI), or using Sigreturn-Oriented Programming (SROP).

**CWE mapping:** CWE-693: Protection Mechanism Failure

**Sources:**
1. Edge, J. 2015. Seccomp and sandboxing. *LWN.net Security Articles*. https://lwn.net/Articles/656302/
2. ir0nstone. 2022. Seccomp Filters and Bypasses. *ir0nstone Notes*. https://ir0nstone.gitbook.io

---

### integer_overflow

**Full name:** Integer Overflow / Underflow

**Alternative names:** Arithmetic wraparound, Signed/unsigned mismatch

**Classification:** Arithmetic validation vulnerability acting as a prerequisite primitive for buffer allocation or bounds check failures.

**Core condition:** Causing an integer value to increment past its maximum representable limit (or decrement below minimum), wrapping around to unexpected small/negative values.

**CWE mapping:** CWE-190: Integer Overflow or Wraparound

**Sources:**
1. MITRE. 2023. CWE-190: Integer Overflow or Wraparound. *CWE Database*. https://cwe.mitre.org/data/definitions/190.html
2. OWASP. 2021. Integer Overflow Vulnerability. *OWASP*. https://owasp.org

---

## Section C: Security Mitigations

### NX: No-Execute / Data Execution Prevention

**Full name and common abbreviations:**
No-Execute (`NX`), Data Execution Prevention (`DEP`), Executable Space Protection, Write XOR Execute (`W^X`).

**What it prevents:**
Mechanistically, `NX` marks memory pages (such as the stack, heap, and data segments) with page table flags preventing the CPU instruction fetcher from executing instructions located within those memory ranges. Attempting to jump to an `NX`-protected address triggers a hardware page fault faulting execution with a Segmentation Fault (`SIGSEGV`).

**Implementation:**
Enforced via hardware CPU page table memory management unit (MMU) architecture (the `NX` bit on x86-64 / AMD64, `XN` bit on ARM). Linux compilers flag ELF binaries using the `PT_GNU_STACK` segment header; setting permissions to `RW` (Read/Write) disables the `E` (Execute) flag.

**BinExplain reporting:**
BinExplain reports binary protection status as `NX: Enabled` or `NX: Disabled`.

**Techniques that bypass or defeat it:**
- `ret2libc` (executes existing code in `.text` or library spaces)
- `rop_chain` (chains executable code fragments terminating in `ret`)
- `format_string` (reads/writes memory directly without executing data segments)

**Techniques blocked by it:**
- `shellcode` / `shellcode_injection` (direct machine code execution in stack/heap buffers)

**Real-world cases / CVEs:**
1. **CVE-2003-0352 (MS03-026 Blaster Worm):** Buffer overflow in RPC DCOM allowing shellcode execution on unpatched systems prior to hardware DEP enforcement.
2. **CVE-2010-3333 (Microsoft Word RTF Stack Overflow):** Exploited stack buffers via raw shellcode on platforms lacking mandatory DEP enforcement.

**Sources:**
1. AMD. 2005. AMD64 Architecture Programmer's Manual Volume 2: System Programming (No-Execute Bit Specifications). *AMD Corporation*.
2. Microsoft. 2021. Data Execution Prevention (DEP) Technical Overview. *Microsoft Security Documentation*.
3. MITRE D3FEND. 2023. D3-EXEC: Segment Execution Prevention. *MITRE D3FEND Matrix*. https://d3fend.mitre.org/technique/d3fend:SegmentExecutionPrevention/

---

### PIE: Position Independent Executable

**Full name and common abbreviations:**
Position Independent Executable (`PIE`), Position Independent Code (`PIC`), Address Space Layout Randomization (`ASLR`).

**What it prevents:**
`PIE` forces the main executable binary image to compile as a position-independent shared object. When loaded, kernel `ASLR` randomizes the base virtual memory address of the process code (`.text`), read-only data (`.rodata`), and data structures (`.got`, `.bss`) on every execution, preventing static memory address reference attacks.

**Implementation:**
Compiler generates position-independent relative addressing instructions (`GCC -fPIE -pie`). Linker creates an ELF type of `ET_DYN` (shared object) rather than `ET_EXEC` (executable). The ELF program loader loads the binary image at a randomized memory offset chosen at runtime by the Linux kernel `sysctl kernel.randomize_va_space`.

**BinExplain reporting:**
BinExplain reports binary protection status as `PIE: Enabled` or `PIE: Disabled` (or `No PIE`).

**Techniques that bypass or defeat it:**
- `aslr_bypass` (leaking runtime pointers via `format_string_leak` or out-of-bounds reads to calculate static relative base offsets)
- Partial overwrites (overwriting only the lowest 2 bytes of pointers when ASLR page alignment matches)

**Techniques blocked by it:**
- Hardcoded return address overwrites (`ret2win` or `ret2libc` using absolute fixed memory addresses)
- Static ROP chains utilizing fixed non-PIE binary gadget offsets

**Real-world cases / CVEs:**
1. **CVE-2017-5754 (Meltdown):** Highlighted the critical requirement of randomized base addresses across process boundaries.
2. **CVE-2019-14287 (Sudo privilege escalation):** Non-PIE static address assumptions allowed reliable local privilege escalation chains.

**Sources:**
1. Shacham, H. et al. 2004. On the effectiveness of address-space randomization. In *Proceedings of the 11th ACM Conference on Computer and Communications Security (CCS '04)*. ACM, 298–307. https://doi.org/10.1145/1030083.1030124
2. Red Hat. 2020. Position Independent Executables (PIE) in Linux Packaging. *Red Hat Security Hardening Guide*.
3. MITRE D3FEND. 2023. D3-AZR: Process Address Space Randomization. *MITRE D3FEND Matrix*. https://d3fend.mitre.org/technique/d3fend:ProcessAddressSpaceRandomization/

---

### Stack Canary: Stack Smashing Protector

**Full name and common abbreviations:**
Stack Canary, Stack Cookie, Stack Smashing Protector (`SSP`), ProPolice, `-fstack-protector`.

**What it prevents:**
Mechanistically, a Stack Canary prevents linear stack buffer overflows from overwriting the saved frame pointer (`RBP`) and saved instruction pointer (`RIP`). A random secret guard value is placed on the stack frame between local variables and control records; before returning from a function, the runtime checks whether the canary value was altered.

**Implementation:**
Inserted by compilers (`GCC -fstack-protector-all`). At function entry, the compiler emits code reading a secret guard word from thread-local storage (`fs:0x28` on x86_64 Linux) and writes it onto the stack frame. Prior to executing `ret`, compiler code compares the stack value against `fs:0x28`. If a mismatch occurs, execution aborts immediately via `__stack_chk_fail()`.

**BinExplain reporting:**
BinExplain reports binary protection status as `Canary: Found` or `Canary: No Canary Found`.

**Techniques that bypass or defeat it:**
- `canary_bypass` (leaking canary bytes via `format_string_leak` or out-of-bounds read and writing them back intact during buffer overflow)
- Arbitrary write primitives (`got_overwrite`, `format_string_write`, heap exploitation targeting pointers outside the stack frame without corrupting stack memory)
- Fork-server brute-forcing (guessing canary values byte-by-byte in child processes that inherit parent thread-local storage values)

**Techniques blocked by it:**
- Unchecked contiguous stack buffer overflows attempting direct return address overwrite (`ret2win`, `ret2libc`, `rop_chain` via direct linear overflow)

**Real-world cases / CVEs:**
1. **CVE-2012-0883 (Apache HTTP Server Buffer Overflow):** Absence of consistent stack canary compilation permitted direct stack return address control.
2. **CVE-2015-3456 (VENOM Floppy Disk Controller Vulnerability):** Stack buffer overflow in QEMU mitigated on systems maintaining strict GCC SSP flags.

**Sources:**
1. Cowan, C. et al. 1998. StackGuard: Automatic adaptive detection and prevention of buffer-overflow attacks. In *Proceedings of the 7th USENIX Security Symposium (USENIX Security '98)*. 63–78.
2. ir0nstone. 2022. Stack Canaries. *ir0nstone Security Notes*. https://ir0nstone.gitbook.io/notes/types/stack/canaries
3. MITRE D3FEND. 2023. D3-SCC: Stack Frame Canary Integrity Verification. *MITRE D3FEND Matrix*. https://d3fend.mitre.org/technique/d3fend:StackFrameCanaryIntegrityVerification/

---

### RELRO: Relocation Read-Only

**Full name and common abbreviations:**
Relocation Read-Only (`RELRO`), Partial RELRO, Full RELRO.

**What it prevents:**
`RELRO` prevents attackers from overwriting dynamic linker data structures—specifically the Global Offset Table (`GOT`)—to redirect library function calls to arbitrary malicious addresses.

**Implementation:**
Enforced during linking (`GCC -Wl,-z,relro,-z,now`). 
- **Partial RELRO:** The linker reorders dynamic ELF memory sections so that non-writable sections follow writable ones, placing internal headers (`.ctors`, `.dtors`, `.jcr`, `.dynamic`) ahead of the GOT, and marks the non-PLT GOT section read-only after initialization. However, the `.got.plt` section remains writable to allow lazy binding symbol resolution.
- **Full RELRO:** Disables lazy binding entirely (`-z now`). All dynamic symbols are resolved during process startup, after which the entire `.got` and `.got.plt` sections are marked read-only (`RO`) in page tables before control transfers to `main()`.

**BinExplain reporting:**
BinExplain reports binary protection status across three distinct states: `RELRO: None`, `RELRO: Partial RELRO`, or `RELRO: Full RELRO`.

**Techniques that bypass or defeat it:**
- Under Partial or No RELRO: `got_overwrite` (overwriting `.got.plt` entries via format string or heap primitives)
- Under Full RELRO: Redirecting execution via stack frame modifications, function pointers in heap/data sections, or libc hooks (`__free_hook`, `__malloc_hook` in older glibc releases) instead of GOT tables

**Techniques blocked by it:**
- `got_overwrite` (Full RELRO renders the GOT completely read-only, causing segmentation faults on write attempts)

**Real-world cases / CVEs:**
1. **CVE-2014-0160 (Heartbleed):** Memory extraction exploits combined with writable GOT headers under partial RELRO environments enabled reliable control hijacking.
2. **CVE-2021-3156 (Baron Samedit - Sudo Heap Overflow):** Full RELRO forced exploit authors to target heap structures and glibc state objects rather than executing simple GOT overwrites.

**Sources:**
1. Red Hat. 2018. Hardening ELF Binaries with RELRO. *Red Hat Enterprise Linux Security Documentation*.
2. ir0nstone. 2022. RELRO - Relocation Read-Only. *ir0nstone Security Notes*. https://ir0nstone.gitbook.io/notes/types/stack/relro
3. MITRE D3FEND. 2023. D3-WRO: Memory Segment Read-Only Protection. *MITRE D3FEND Matrix*. https://d3fend.mitre.org/technique/d3fend:MemorySegmentReadOnlyProtection/

---

### Fortify: FORTIFY_SOURCE

**Full name and common abbreviations:**
FORTIFY_SOURCE, GCC Fortify Source, Compiler Security Checks (`-D_FORTIFY_SOURCE=2` / `-D_FORTIFY_SOURCE=3`).

**What it prevents:**
`FORTIFY_SOURCE` detects and prevents buffer overflows in common C standard library string and memory manipulation functions (e.g., `strcpy`, `memcpy`, `memset`, `sprintf`, `printf`, `read`) when buffer sizes can be computed at compile time.

**Implementation:**
Implemented via GCC/Clang built-ins and glibc wrapper headers (`-O2 -D_FORTIFY_SOURCE=2`). Compiler calculates buffer allocation sizes using `__builtin_object_size()`. Replaces calls to vulnerable functions with security-checked variants (e.g., replacing `strcpy()` with `__strcpy_chk()`). If a copy operation exceeds the static destination buffer size, the runtime immediately terminates the program via `__chk_fail()`. Additionally, it disables `%n` format string specifiers when format strings reside in writable memory.

**BinExplain reporting:**
BinExplain reports protection status as `Fortify: Enabled` or `Fortify: Disabled`.

**Techniques that bypass or defeat it:**
- Dynamic buffer allocations where the compiler cannot determine target buffer capacities at compile time (`__builtin_object_size` returns `-1`)
- Overflows in non-fortified custom memory loop implementations
- Direct pointer corruption or Use-After-Free primitives

**Techniques blocked by it:**
- Known static string buffer overflows (`ret2win`, `ret2libc`, `shellcode` attempting linear stack overflows via simple fortified library calls like `gets` or `strcpy`)
- Unchecked format string write specifiers (`%n` format string writes in writable memory)

**Real-world cases / CVEs:**
1. **CVE-2020-1971 (OpenSSL ASN.1 Null Pointer Dereference / Buffer Overflow):** Fortified runtime wrappers prevented secondary memory corruption escalation paths in distributions shipping fortified binaries.
2. **CVE-2023-4911 (Looney Tunables - glibc `ld.so` Buffer Overflow):** Vulnerability occurred in dynamic linker setup prior to execution of fortified C library wrapper calls.

**Sources:**
1. GNU Project. 2022. The GNU C Library: Source Fortification Flags (`_FORTIFY_SOURCE`). *GNU Software Manual*.
2. Red Hat. 2019. Enhancing security with _FORTIFY_SOURCE. *Red Hat Developer Blog*. https://developers.redhat.com
3. MITRE D3FEND. 2023. D3-BCK: Built-in Boundary Check Enforcement. *MITRE D3FEND Matrix*. https://d3fend.mitre.org/technique/d3fend:BuiltInBoundaryCheckEnforcement/

---

## Relationship Map

The following matrix documents the interaction between binary security mitigations and BinExplain primary archetypes.

| Primary Archetype | NX (No-Execute) | PIE (Position Independent Executable) | Stack Canary | RELRO (Full RELRO) | Fortify (`FORTIFY_SOURCE`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ret2win` | NO EFFECT<sup>1</sup> | COMPLICATES<sup>2</sup> | BLOCKS<sup>3</sup> | NO EFFECT<sup>1</sup> | BLOCKS<sup>4</sup> |
| `ret2libc` | NO EFFECT<sup>1</sup> | COMPLICATES<sup>2</sup> | BLOCKS<sup>3</sup> | NO EFFECT<sup>1</sup> | COMPLICATES<sup>4</sup> |
| `format_string` | NO EFFECT<sup>1</sup> | COMPLICATES<sup>2</sup> | NO EFFECT<sup>5</sup> | BLOCKS<sup>6</sup> | BLOCKS<sup>7</sup> |
| `heap_exploitation` | NO EFFECT<sup>1</sup> | COMPLICATES<sup>2</sup> | NO EFFECT<sup>5</sup> | COMPLICATES<sup>8</sup> | NO EFFECT<sup>1</sup> |
| `rop_chain` | NO EFFECT<sup>1</sup> | COMPLICATES<sup>2</sup> | BLOCKS<sup>3</sup> | NO EFFECT<sup>1</sup> | COMPLICATES<sup>4</sup> |
| `shellcode` | BLOCKS<sup>9</sup> | COMPLICATES<sup>2</sup> | BLOCKS<sup>3</sup> | NO EFFECT<sup>1</sup> | BLOCKS<sup>4</sup> |

### Matrix Footnotes and Definitions

- **`BLOCKS`**: The mitigation mechanisms rendered the fundamental primitive of the archetype unusable in its default form, requiring complete neutralization or replacement of the attack vector.
- **`COMPLICATES`**: The mitigation does not block the attack vector entirely, but requires an extra exploitation step (e.g., an information leak, offset computation, or stack pivot) to succeed.
- **`NO EFFECT`**: The mitigation does not impede or interfere with the operational mechanics of the specified archetype.

1. *NO EFFECT:* `NX` only prevents instruction execution in data pages (stack/heap). Archetypes relying on existing executable code segments (`.text`, shared libraries) are inherently immune to `NX`.
2. *COMPLICATES:* `PIE` randomizes process base addresses. It complicates exploitation by requiring an address leak (`aslr_bypass`) to compute target addresses at runtime.
3. *BLOCKS:* Stack Canaries detect linear writes over saved frame pointers. Any linear stack buffer overflow attempting return address modification triggers `__stack_chk_fail()` and terminates execution.
4. *BLOCKS / COMPLICATES:* `FORTIFY_SOURCE` replaces unbounded functions (`strcpy`, `gets`) with checked calls (`__strcpy_chk`), blocking static overflows. Overflows in non-fortified functions remain possible but complicated.
5. *NO EFFECT:* Format string and heap vulnerabilities target data/pointers outside stack frame return pointers, bypassing canary checks completely.
6. *BLOCKS:* Full RELRO marks the Global Offset Table (`.got`) read-only, entirely preventing `format_string` `%n` writes from overwriting GOT entries (`got_overwrite`).
7. *BLOCKS:* `FORTIFY_SOURCE` explicitly disables `%n` format specifiers when format strings originate from writable memory regions.
8. *COMPLICATES:* Full RELRO prevents heap arbitrary write primitives from overwriting GOT entries, forcing attack chains to target heap state, libc hooks, or stack pointers instead.
9. *BLOCKS:* `NX` explicitly marks stack and heap memory non-executable, directly blocking raw shellcode machine instruction execution.

---

## References

1. AMD. 2005. *AMD64 Architecture Programmer's Manual Volume 2: System Programming*. Publication No. 24593. AMD Corporation.
2. Buchanan, E., Roemer, R., Shacham, H., and Savage, S. 2008. When good instructions go bad: Generalizing return-oriented programming to RISC. In *Proceedings of the 15th ACM Conference on Computer and Communications Security (CCS '08)*. ACM, New York, NY, USA, 27–38. https://doi.org/10.1145/1455770.1455776
3. Cowan, C., Pu, C., Maier, D., Hinton, H., Walpole, J., Bakke, P., Beattie, S., Grier, A., Wagle, P., and Zhang, Q. 1998. StackGuard: Automatic adaptive detection and prevention of buffer-overflow attacks. In *Proceedings of the 7th USENIX Security Symposium (USENIX Security '98)*. USENIX Association, Berkeley, CA, USA, 63–78.
4. david942j. 2016. `one_gadget`: Tool for finding one gadget RCE in libc. *GitHub Repository*. Retrieved July 28, 2026 from https://github.com/david942j/one_gadget
5. Edge, J. 2015. Seccomp and sandboxing. *LWN.net Technical Articles*. Retrieved July 28, 2026 from https://lwn.net/Articles/656302/
6. Foster, J.C., Price, M., Soderlund, C., and Beaver, N. 2005. *Buffer Overflow Attacks: Detect, Exploit, Prevent*. Syngress Publishing. ISBN: 978-1597490221.
7. GNU Project. 2022. *The GNU C Library Reference Manual: Source Fortification Flags*. Free Software Foundation. Retrieved July 28, 2026 from https://www.gnu.org/software/libc/manual/
8. Guyinatuxedo. 2020. Nightmare: A CTF course based on real world vulnerabilities and binary exploitation. *Nightmare Tutorials*. Retrieved July 28, 2026 from https://guyinatuxedo.github.io/
9. ir0nstone. 2022. *ir0nstone's Security Notes: Binary Exploitation*. GitBook Guide. Retrieved July 28, 2026 from https://ir0nstone.gitbook.io/notes/
10. Kaempf, M. 2001. Vudo - An object-oriented approach to malloc() exploitation. *Phrack Magazine*, Vol. 11, Issue 57. Retrieved July 28, 2026 from http://phrack.org/issues/57/8.html
11. Microsoft. 2021. Data Execution Prevention (DEP) Technical Overview. *Microsoft Security Documentation*. Retrieved July 28, 2026 from https://learn.microsoft.com
12. MITRE. 2023. Common Weakness Enumeration (CWE) Database. *MITRE Corporation*. Retrieved July 28, 2026 from https://cwe.mitre.org/
13. MITRE D3FEND. 2023. Cybersecurity Countermeasure Architecture Matrix. *MITRE D3FEND*. Retrieved July 28, 2026 from https://d3fend.mitre.org/
14. Newsham, T. 2000. Format String Attacks. *Guardent, Inc. Technical Paper*. Retrieved July 28, 2026 from https://cgisecurity.com/lib/formatstring-1.2.pdf
15. One, A. 1996. Smashing The Stack For Fun And Profit. *Phrack Magazine*, Vol. 7, Issue 49. Retrieved July 28, 2026 from http://phrack.org/issues/49/14.html
16. OWASP. 2021. OWASP Software Security Vulnerabilities Documentation. *OWASP Foundation*. Retrieved July 28, 2026 from https://owasp.org
17. pwn.college. 2023. Cybersecurity Education and Binary Exploitation Modules. *pwn.college Security Course*. Retrieved July 28, 2026 from https://pwn.college/
18. pwntools. 2023. pwntools: CTF framework and exploit development library documentation. *Gallopsled pwntools*. Retrieved July 28, 2026 from https://docs.pwntools.com/
19. Red Hat. 2020. *Red Hat Enterprise Linux 8 Security Hardening Guide*. Red Hat Documentation. Retrieved July 28, 2026 from https://access.redhat.com
20. Roemer, R., Buchanan, E., Shacham, H., and Savage, S. 2012. Return-oriented programming: Systems, languages, and applications. *ACM Transactions on Information and System Security (TISSEC)* 15, 1 (2012), 2:1–2:34. https://doi.org/10.1145/2133375.2133377
21. Shacham, H. 2007. The geometry of innocent flesh on the bone: Return-into-libc without function calls (on the x86). In *Proceedings of the 14th ACM Conference on Computer and Communications Security (CCS '07)*. ACM, New York, NY, USA, 552–561. https://doi.org/10.1145/1315245.1315313
22. Shacham, H., Page, M., Pfaff, B., Goh, E.J., Modadugu, N., and Boneh, D. 2004. On the effectiveness of address-space randomization. In *Proceedings of the 11th ACM Conference on Computer and Communications Security (CCS '04)*. ACM, New York, NY, USA, 298–307. https://doi.org/10.1145/1030083.1030124
23. Shellphish. 2023. `how2heap`: A repository for learning heap exploitation. *GitHub Security Repository*. Retrieved July 28, 2026 from https://github.com/shellphish/how2heap
