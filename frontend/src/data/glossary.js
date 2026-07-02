export const GLOSSARY = {
  "buffer overflow": {
    simple: "When you pour more water into a glass than it can hold and it spills over. In software, when a program receives more data than its memory container can hold, the extra data spills into adjacent memory.",
    example: "The 2003 Slammer worm exploited a buffer overflow in Microsoft SQL Server. It spread to 75,000 machines in 10 minutes and caused $1.2 billion in damages by sending a single 376-byte packet that overflowed a buffer and executed malicious code."
  },
  "stack": {
    simple: "A pile of plates in a cafeteria. You always add and remove from the top. Your program uses this to remember where to return after calling a function.",
    example: "When you call a function in your code, the program pushes a 'return address' onto the stack — like putting a bookmark in a book. Buffer overflows often target this return address to hijack program execution."
  },
  "heap": {
    simple: "A messy storage room where your program puts things it needs to remember for a long time. Unlike the stack, items can be placed anywhere and removed in any order.",
    example: "The 2014 Heartbleed bug exploited heap memory in OpenSSL. Attackers could read 64KB of heap memory per request, leaking private keys, passwords, and session tokens from millions of HTTPS servers including Yahoo and Amazon."
  },
  "return address": {
    simple: "A sticky note that tells your program where to go back after it finishes doing something. Attackers try to change this sticky note to redirect the program to their own malicious code.",
    example: "In the Morris Worm of 1988 — the first major internet worm — attackers overwrote return addresses to make programs execute their shellcode instead of returning normally. It infected 6,000 machines (10% of the internet at the time)."
  },
  "shellcode": {
    simple: "A tiny program hidden inside an attack. When executed, it usually opens a command shell giving the attacker full control of the system.",
    example: "The 2017 WannaCry ransomware used shellcode injected via the EternalBlue exploit to gain system access, then encrypted files on 200,000 computers across 150 countries causing $4 billion in damage."
  },
  "ROP": {
    simple: "Return Oriented Programming. Instead of injecting new malicious code, the attacker reuses small pieces of the program's own code (called gadgets) chained together to do something malicious. Like building a sentence using only words already in a book.",
    example: "Modern exploits use ROP to bypass DEP/NX protections. The 2015 Stagefright Android vulnerability used ROP chains to achieve code execution on 950 million Android devices without NX bypass."
  },
  "rop chain": {
    simple: "A sequence of code snippets already in the program, chained together like LEGO bricks to perform an attack. Each piece ends with a 'return' instruction that jumps to the next piece.",
    example: "JailbreakMe used ROP chains to jailbreak iOS devices. By simply visiting a website, the exploit chained existing iOS code snippets to bypass all security protections and gain root access."
  },
  "NX": {
    simple: "No-Execute. A rule that says memory used for data cannot be executed as code. Like a kitchen rule: ingredients can only be stored in the fridge, not cooked in it.",
    example: "NX/DEP was introduced after the early 2000s shellcode epidemic. Before NX, the Sasser worm (2004) injected and executed shellcode directly in stack memory, infecting 1 million Windows XP machines."
  },
  "PIE": {
    simple: "Position Independent Executable. Every time the program runs, it loads at a random memory address. Like changing the location of your house every day so attackers can't find it.",
    example: "Without PIE, the 2006 ANI exploit could hardcode exact memory addresses to attack Windows systems. PIE forces attackers to first leak an address before they can use it, adding a significant exploitation step."
  },
  "ASLR": {
    simple: "Address Space Layout Randomization. The operating system shuffles where everything in memory is placed each time a program runs. Makes it much harder for attackers to predict where to jump.",
    example: "Before ASLR was widely adopted, the 2004 Sasser worm hardcoded memory addresses that worked on every Windows XP machine. ASLR made such attacks far harder by randomizing these addresses."
  },
  "canary": {
    simple: "A secret value placed between your data and the return address. Before the program returns, it checks if the canary value changed. If it did, a buffer overflow happened. Named after canaries in coal mines that warned of danger.",
    example: "Stack canaries were developed after the 1988 Morris Worm. They detect the moment a buffer overflow overwrites the return address. The program immediately crashes instead of executing attacker code."
  },
  "RELRO": {
    simple: "Relocation Read-Only. Makes certain memory areas read-only after the program starts so attackers cannot write malicious addresses there. Like putting a lock on a filing cabinet after the office opens.",
    example: "Without Full RELRO, attackers can overwrite the Global Offset Table (GOT) to redirect function calls. GOT overwrites were used in numerous CTF challenges and real exploits to hijack program execution."
  },
  "GOT": {
    simple: "Global Offset Table. A lookup table your program uses to find external functions like printf or system. Attackers try to overwrite entries here to redirect function calls to malicious code.",
    example: "GOT overwrites are a classic CTF technique. In real attacks, the 2009 Apache vulnerability allowed GOT poisoning to redirect legitimate function calls to attacker shellcode."
  },
  "PLT": {
    simple: "Procedure Linkage Table. The middleman between your code and external libraries. When your program calls printf, it goes through the PLT first. Attackers abuse this to call functions like system().",
    example: "ret2plt attacks use the PLT to call library functions without knowing their exact address. This bypasses ASLR by using the PLT as a stable trampoline to reach libc functions."
  },
  "format string": {
    simple: "A vulnerability where user input is treated as formatting instructions. Like if someone could inject commands into a form by writing special characters instead of their name.",
    example: "The 2000 wu-ftpd format string vulnerability affected millions of FTP servers. Attackers sent %n format specifiers as usernames, writing arbitrary values to memory and gaining root access on servers worldwide."
  },
  "libc": {
    simple: "The C Standard Library. A collection of common functions every C program uses — like printf, malloc, and system. Attackers love it because it contains system() which can run shell commands.",
    example: "ret2libc attacks redirect execution to the system() function inside libc to spawn a shell. This bypasses NX because you are reusing existing code instead of injecting new shellcode."
  },
  "ret2libc": {
    simple: "An attack that redirects a program's return address to the system() function inside libc, passing '/bin/sh' as the argument to open a shell. Bypasses NX/DEP because no new code is injected.",
    example: "ret2libc was documented as early as 1997 by Solar Designer and remains one of the most common CTF techniques. It works even on modern systems when combined with an address leak to bypass ASLR."
  },
  "ret2win": {
    simple: "The simplest CTF exploit type. The binary has a secret win() or flag() function that prints the flag. You just need to overflow a buffer and redirect execution to jump directly to that function.",
    example: "ret2win challenges appear in nearly every beginner CTF including picoCTF. They teach the fundamental concept of controlling a program's execution flow through a buffer overflow."
  },
  "use after free": {
    simple: "Using a piece of memory after you have already given it back (freed it). Like throwing away a key to a storage unit but still trying to use what's inside — someone else might have moved in.",
    example: "The 2014 Internet Explorer UAF vulnerability (CVE-2014-1776) was used in Operation Clandestine Fox to target US defense contractors. Attackers freed a CMarkup object then accessed it again to achieve code execution."
  },
  "tcache": {
    simple: "A fast memory recycling bin in modern Linux. When you free small chunks of memory, they go here first for quick reuse. Attackers can poison this cache to make malloc return malicious addresses.",
    example: "Tcache was introduced in glibc 2.26 (2017) as a performance optimization. Almost immediately CTF challenge designers started using tcache poisoning as an exploitation technique in heap challenges."
  },
  "malloc": {
    simple: "Memory Allocate. A function that requests a chunk of memory from the heap. Like asking a librarian for a specific sized box to store your stuff.",
    example: "malloc vulnerabilities include heap overflow, use-after-free, and double-free. The 2003 Linux kernel do_mremap() bug exploited a heap overflow in kernel malloc to achieve privilege escalation."
  },
  "free": {
    simple: "Gives a chunk of memory back to the heap so it can be reused. Mistakes with free (freeing twice, using after freeing) are among the most exploited vulnerabilities in modern systems.",
    example: "Double-free bugs occur when free() is called twice on the same pointer. CVE-2019-11932 in WhatsApp used a double-free in image parsing to achieve remote code execution on 1.5 billion devices."
  },
  "checksec": {
    simple: "A tool that checks which security protections are enabled in a binary. Like a security audit that tells you which locks are on the doors and which windows are left open.",
    example: "CTF players run checksec as the first step on every binary challenge. The protections it reports (NX, PIE, Canary, RELRO) directly determine which exploitation techniques are available."
  },
  "pwntools": {
    simple: "A Python library specifically built for CTF exploitation. It handles connecting to remote servers, sending payloads, and interacting with running processes so you can focus on the exploit logic.",
    example: "pwntools is used in virtually every competitive CTF team. The Shellphish team from UC Santa Barbara used pwntools-based exploits to win multiple DEFCON CTF competitions."
  },
  "ELF": {
    simple: "Executable and Linkable Format. The file format for programs on Linux, like how .exe is the format for Windows. ELF files contain the program code, data, and metadata the OS needs to run it.",
    example: "When you download a CTF binary, it is almost always an ELF file. Tools like readelf and objdump parse ELF headers to reveal program structure, sections, symbols, and security properties."
  },
  "GDB": {
    simple: "GNU Debugger. A tool that lets you pause a running program, look at memory, step through instructions one at a time, and inspect register values. Essential for understanding what a binary does.",
    example: "CTF players use GDB with plugins like pwndbg or peda. Security researchers used GDB to analyze the Stuxnet worm in 2010, helping them understand and document the first known cyberweapon targeting industrial control systems."
  },
  "CVE": {
    simple: "Common Vulnerabilities and Exposures. A standardized ID number assigned to publicly known security vulnerabilities. Like a serial number for bugs that lets the security community reference and track them.",
    example: "CVE-2021-44228 is Log4Shell, one of the most critical vulnerabilities ever found. It affected millions of servers and was exploited within hours of disclosure. Every major vulnerability you hear about has a CVE number."
  },
  "CVSS": {
    simple: "Common Vulnerability Scoring System. A score from 0 to 10 that measures how severe a vulnerability is. Above 9.0 is Critical, 7-9 is High, 4-7 is Medium, below 4 is Low.",
    example: "Log4Shell received a CVSS score of 10.0 — the maximum possible. This score indicated it was remotely exploitable, required no authentication, and had full impact on confidentiality, integrity, and availability."
  },
  "offset": {
    simple: "The exact number of bytes you need to fill before you reach the return address on the stack. Get this number right and you control where the program jumps next.",
    example: "In a typical ret2win CTF challenge, if the buffer is 64 bytes and there is 8 bytes of saved frame pointer before the return address, the offset is 72. You fill 72 bytes of padding then write your target address."
  },
  "gadget": {
    simple: "A short sequence of existing instructions in a binary that ends with a 'ret' instruction. Attackers chain gadgets together to build ROP chains that perform arbitrary operations without injecting new code.",
    example: "Tools like ROPgadget and ropper automatically find gadgets in binaries. The most useful gadget is 'pop rdi; ret' which lets you control the first argument to any function call in 64-bit Linux."
  },
  "objdump": {
    simple: "A tool that disassembles a binary, showing you the assembly instructions inside. Like an X-ray machine for programs that lets you see the machine code without running the program.",
    example: "objdump -d is one of the first commands CTF players run on a binary challenge. Security researchers used disassembly tools to analyze the Mirai botnet source code in 2016, revealing how it attacked IoT devices."
  },
  "disassembly": {
    simple: "Converting machine code (binary instructions the CPU understands) back into human-readable assembly language. Like translating morse code back into English.",
    example: "Reverse engineers disassemble malware to understand what it does without running it. The disassembly of Stuxnet revealed it specifically targeted Siemens STEP 7 software used in Iranian nuclear centrifuges."
  },
  "payload": {
    simple: "The malicious data you send to exploit a vulnerability. In CTF, your payload typically consists of padding to fill a buffer plus the address you want to jump to.",
    example: "A classic ret2win payload is: 'A' * offset + p64(win_function_address). The A's fill the buffer, and the address overwrites the return address to redirect execution to the win function."
  },
  "segfault": {
    simple: "Segmentation Fault. The program crashed because it tried to access memory it is not allowed to touch. In exploitation, a segfault usually means your payload reached the return address — you just need to fix the address.",
    example: "When developing a CTF exploit, getting a segfault at a recognizable address (like 0x4141414141414141 from AAAA...) confirms you have found the correct offset and now control the return address."
  },
};

export const findGlossaryTerms = (text) => {
  if (!text) return [];
  const terms = Object.keys(GLOSSARY);
  const found = [];
  const textLower = text.toLowerCase();
  for (const term of terms) {
    if (textLower.includes(term.toLowerCase())) {
      found.push(term);
    }
  }
  // Sort by length descending so longer terms match before shorter ones
  // (e.g. "buffer overflow" matches before "buffer")
  return found.sort((a, b) => b.length - a.length);
};
