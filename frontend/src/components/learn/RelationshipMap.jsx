import React, { useState, useRef, useEffect } from 'react';

const NODES = {
  gets: {
    id: 'gets',
    label: 'gets()',
    col: 1,
    left: 10,
    top: 50,
    desc: 'Reads user input until a newline. It does not check boundaries, making it highly vulnerable to buffer overflows.',
    explanation: "gets() is a legacy C library function used to read text input from a user. It is critically dangerous because it has no bounds checking, meaning it will read data indefinitely until it hits a newline, making stack overflows inevitable if the input is too long."
  },
  printf_buf: {
    id: 'printf_buf',
    label: 'printf(buf)',
    col: 1,
    left: 10,
    top: 140,
    desc: 'Prints a user-controlled buffer without format specifiers. This lets attackers leak or write stack memory.',
    explanation: "printf(buf) is an insecure invocation of the C formatted print function where user input is passed directly as the format string. Because it lacks a static format string argument, a user can supply format parameters like %p or %n to read or write raw stack memory."
  },
  strcpy: {
    id: 'strcpy',
    label: 'strcpy()',
    col: 1,
    left: 10,
    top: 230,
    desc: 'Copies a string to a destination until a null byte. Overflows if the source string is larger than the destination buffer.',
    explanation: "strcpy() copies a source string to a destination buffer pointer until it encounters a null terminator byte. Since it does not check if the source string fits within the destination buffer limits, it frequently causes buffer overflows in memory."
  },
  malloc_free: {
    id: 'malloc_free',
    label: 'malloc() + free()',
    col: 1,
    left: 10,
    top: 320,
    desc: 'Dynamic heap memory allocation routines. Buggy code leads to double-free, use-after-free, or heap chunk overflows.',
    explanation: "malloc() and free() are dynamic memory allocation functions used in C to allocate and release heap memory space. Improper tracking of allocated buffers can lead to memory safety issues like double-freeing or using heap pointers after they have been freed."
  },
  system_fn: {
    id: 'system_fn',
    label: 'system()',
    col: 1,
    left: 10,
    top: 410,
    desc: 'Invokes command shells. If the argument contains unsanitized user inputs, attackers can execute arbitrary shell commands.',
    explanation: "system() is a standard library function used to execute shell commands directly from within a C program. If the argument passed to system() is under user control, it is extremely easy for an attacker to inject arbitrary commands and run shell payloads."
  },
  buffer_overflow: {
    id: 'buffer_overflow',
    label: 'Buffer Overflow',
    col: 2,
    left: 250,
    top: 50,
    desc: 'Writing data beyond stack/heap boundaries, corrupting adjacent program structures like saved return pointers.',
    explanation: "A buffer overflow occurs when a program writes more data to a buffer than it was allocated to hold. This causes the excess data to overflow into and corrupt adjacent memory locations, which can be leveraged to hijack control flow."
  },
  format_string_vuln: {
    id: 'format_string_vuln',
    label: 'Format String Bug',
    col: 2,
    left: 250,
    top: 140,
    desc: 'Occurs when user-supplied inputs are evaluated directly as format variables inside printf calls.',
    explanation: "A format string vulnerability arises when user-controlled data is passed as the first argument of a formatting function like printf. This allows attackers to input format parameters to leak memory pointers or overwrite values at arbitrary addresses."
  },
  heap_corruption: {
    id: 'heap_corruption',
    label: 'Heap Corruption',
    col: 2,
    left: 250,
    top: 230,
    desc: 'Corrupting heap manager headers or bin pointers to hijack subsequent malloc allocations.',
    explanation: "Heap corruption is the unintended modification of the heap memory layout, including chunk headers, sizes, or bin pointers. It is typically caused by heap buffer overflows or double-free bugs, and can be exploited to control dynamic memory allocations."
  },
  use_after_free: {
    id: 'use_after_free',
    label: 'Use-After-Free',
    col: 2,
    left: 250,
    top: 320,
    desc: 'Accessing pointers pointing to heap addresses that have already been released back to the allocator.',
    explanation: "A Use-After-Free vulnerability occurs when a program continues to use a memory pointer after the heap block it references has been freed. If the freed space is reallocated, accessing the dangling pointer can corrupt new data or hijack function pointers."
  },
  got_overwrite: {
    id: 'got_overwrite',
    label: 'GOT Overwrite',
    col: 2,
    left: 250,
    top: 410,
    desc: 'Writing malicious function pointer addresses into the Global Offset Table to hijack library function lookups.',
    explanation: "A Global Offset Table (GOT) overwrite is an exploit technique where the attacker writes a malicious pointer over a library function address inside the GOT. This redirects dynamic function lookups, causing calls to standard functions to jump to exploit code instead."
  },
  ret2win: {
    id: 'ret2win',
    label: 'ret2win',
    col: 3,
    left: 490,
    top: 30,
    desc: 'A beginner attack path where the return address is overwritten to point directly to a secret win() function.',
    explanation: "ret2win is a basic stack buffer overflow technique where the attacker overwrites the return pointer to point directly to a win() or flag() function. When the current function returns, the CPU execution jumps to this function, printing the flag."
  },
  ret2libc: {
    id: 'ret2libc',
    label: 'ret2libc',
    col: 3,
    left: 490,
    top: 110,
    desc: 'Redirects execution to system() within libc, passing "/bin/sh" as an argument to spawn a shell.',
    explanation: "ret2libc (Return-to-libc) is an exploit method used to bypass non-executable stack protections (NX). The attacker overwrites the return address to point to existing standard library functions (like system()) inside libc, executing shell commands."
  },
  format_string: {
    id: 'format_string',
    label: 'format_string',
    col: 3,
    left: 490,
    top: 190,
    desc: 'An attack that exploits format string parameters to leak pointers or perform arbitrary memory writes.',
    explanation: "Format string exploitation targets format parameters inside printf calls to leak address offsets or write data to memory. It is often used to bypass address randomizations (ASLR/PIE) or modify critical control variables directly."
  },
  heap_exploitation: {
    id: 'heap_exploitation',
    label: 'Heap Exploitation',
    col: 3,
    left: 490,
    top: 270,
    desc: 'Taverning heap bin lists (tcache/fastbin) to redirect allocation pointers to target code or variable data.',
    explanation: "Heap exploitation involves manipulating the state of the heap allocator (like libc bins, tcache, or fastbins) to return a pointer to a target address (like the stack or GOT). This allows the attacker to write arbitrary data to that location."
  },
  rop_chain: {
    id: 'rop_chain',
    label: 'ROP Chain',
    col: 3,
    left: 490,
    top: 350,
    desc: 'Return-Oriented Programming. Chaining gadgets to load variables and bypass executable page protections.',
    explanation: "Return-Oriented Programming (ROP) is an advanced exploit technique used to bypass No-Execute (NX) protections. It chains together short sequences of pre-existing executable machine instructions (gadgets) to perform arbitrary logic."
  },
  shellcode: {
    id: 'shellcode',
    label: 'shellcode',
    col: 3,
    left: 490,
    top: 430,
    desc: 'Injecting raw assembly payloads into writable buffers and jumping to them to spawn shells under disabled NX.',
    explanation: "Shellcode is a small piece of machine code injected into a vulnerable program's memory. If memory regions are executable, the attacker overwrites the return address to point to the shellcode, running commands directly."
  },
  nx: {
    id: 'nx',
    label: 'NX / DEP',
    col: 4,
    left: 730,
    top: 50,
    desc: 'No-Execute / Data Execution Prevention. Flags stack/heap pages as non-executable, stopping raw shellcode execution.',
    explanation: "No-Execute (NX), also known as Data Execution Prevention (DEP), is a hardware-enforced mitigation that marks writable memory regions (like the stack or heap) as non-executable. This stops execution of injected shellcode payloads."
  },
  pie: {
    id: 'pie',
    label: 'PIE / ASLR',
    col: 4,
    left: 730,
    top: 140,
    desc: 'Position Independent Executable / Address Space Layout Randomization. Randomizes target instruction locations.',
    explanation: "Position Independent Executable (PIE), combined with Address Space Layout Randomization (ASLR), randomizes the memory addresses of the binary's code, stack, and heap. This makes it difficult to hardcode return address destinations in exploit payloads."
  },
  canary: {
    id: 'canary',
    label: 'Stack Canary',
    col: 4,
    left: 730,
    top: 230,
    desc: 'A secret integer stored before the stack return pointer. Corrupting it triggers bounds checks, crashing the process safely.',
    explanation: "A stack canary is a random value placed on the stack right before the local buffer and the return address. Before a function returns, the canary's value is checked; if it was overwritten, the program crashes immediately, preventing exploitation."
  },
  relro: {
    id: 'relro',
    label: 'RELRO',
    col: 4,
    left: 730,
    top: 320,
    desc: 'ReLocation Read-Only. Locks GOT sectors against dynamic writes, neutralizing GOT overwrite hijacks.',
    explanation: "ReLocation Read-Only (RELRO) is a security mitigation that makes dynamic linker structures, particularly the Global Offset Table (GOT), read-only. This prevents attackers from overwriting dynamic function pointers to redirect execution."
  },
  safe_functions: {
    id: 'safe_functions',
    label: 'Safe Functions',
    col: 4,
    left: 730,
    top: 410,
    desc: 'Bounded alternatives like fgets() and snprintf() that check sizes and eliminate standard overflows.',
    explanation: "Safe functions are bounded alternatives to dangerous C library calls (e.g. using fgets instead of gets, or strncpy instead of strcpy). They enforce buffer size boundaries, eliminating standard stack and heap buffer overflows."
  }
};

const CONNECTIONS = [
  // Col 1 to Col 2
  {
    from: 'gets',
    to: 'buffer_overflow',
    label: 'enables',
    type: 'enable',
    explanation: `gets() reads user input into a buffer but has NO limit on how many bytes it reads. If the user types more than the buffer can hold, the extra bytes overflow into adjacent memory — specifically into the saved return address above it on the stack. This is why gets() was officially removed from the C standard in C11. Never use gets().`
  },
  {
    from: 'gets',
    to: 'ret2win',
    label: 'direct path to',
    type: 'enable',
    explanation: `When gets() overflows into the return address, you control where the program goes next when the function returns. If there is a win() or flag() function in the binary, you simply write its address over the return address. The program then jumps there and prints the flag. This is the simplest exploitation path — one overflow, one address, done.`
  },
  {
    from: 'gets',
    to: 'rop_chain',
    label: 'if NX on',
    type: 'enable',
    explanation: `If NX is enabled, gets() cannot execute shellcode on the stack, but the stack overflow can still overwrite the return address. Instead of returning to shellcode, we return to the first gadget in a ROP chain. Since gets() allows arbitrary overflow sizes, it is easy to write a long ROP chain directly onto the stack.`
  },
  {
    from: 'printf_buf',
    to: 'format_string_vuln',
    label: 'enables',
    type: 'enable',
    explanation: `printf() interprets special format codes in its first argument: %d reads an integer, %s reads a string, %p reads a pointer, %n WRITES to memory. When printf(user_input) is called without a format string like printf("%s", user_input), the user controls what printf interprets. Sending %p%p%p leaks stack addresses. Sending %n writes values to memory. One missing "%s" creates arbitrary read/write.`
  },
  {
    from: 'printf_buf',
    to: 'got_overwrite',
    label: 'enables',
    type: 'enable',
    explanation: `By using format specifiers like %n inside a vulnerable printf(user_input) call, you can write arbitrary values to arbitrary addresses. By targeting the writable Global Offset Table (GOT), you can replace the address of a library function like printf() with the address of system(). The next call to printf() will run system() instead.`
  },
  {
    from: 'strcpy',
    to: 'buffer_overflow',
    label: 'enables',
    type: 'enable',
    explanation: `strcpy() copies a source string to a destination buffer until it hits a null byte (\\0). It does not perform bounds checking on the destination. If the source string is longer than the destination buffer, strcpy() continues writing anyway, overflowing the buffer and corrupting adjacent stack variables and the saved return pointer.`
  },
  {
    from: 'malloc_free',
    to: 'heap_corruption',
    label: 'enables',
    type: 'enable',
    explanation: `malloc() and free() manage heap memory using hidden metadata stored between allocations. A typical chunk looks like: [size: 8 bytes][flags: 8 bytes][user data: N bytes][next chunk metadata...]. Overflowing the user data overwrites the next chunk's metadata. Freeing a chunk twice (double-free) corrupts the freelist. Either lets an attacker make malloc() return an arbitrary address on the next call.`
  },
  {
    from: 'malloc_free',
    to: 'use_after_free',
    label: 'enables',
    type: 'enable',
    explanation: `When a heap buffer is freed using free(), the program should clear its pointer. If it does not, the pointer becomes a 'dangling pointer'. The program can still read or write to it. If malloc() later allocates that same memory chunk to a different object, writing to the dangling pointer will corrupt the new object's data or hijack its function pointers.`
  },
  {
    from: 'system_fn',
    to: 'ret2libc',
    label: 'calls system()',
    type: 'enable',
    explanation: `The system() function from libc runs command shells directly (e.g. executing "/bin/sh"). In a ret2libc attack, the goal is to hijack control flow and jump to the address of system(), passing the string "/bin/sh" as its first parameter. Having system() compiled in or available via shared libraries makes this attack directly possible.`
  },

  // Col 2 to Col 3
  {
    from: 'buffer_overflow',
    to: 'ret2win',
    label: 'exploited via',
    type: 'technique',
    explanation: `A buffer overflow that reaches the return address gives you control of program execution. If a win function exists at a known address (common when PIE is disabled), you write that address directly. Payload structure: [PADDING to reach return address] + [8-byte win() address] The padding length is the overflow offset — BinExplain predicts this from the stack allocation instruction in the disassembly.`
  },
  {
    from: 'buffer_overflow',
    to: 'ret2libc',
    label: 'exploited via',
    type: 'technique',
    explanation: `A buffer overflow overwrites the stack return pointer. If no local win() function exists, you can return to library functions inside libc, like system(). You craft a fake stack frame containing: [PADDING] + [address of system()] + [dummy return address] + [address of "/bin/sh" string]. This jumps directly to system("/bin/sh") on function return.`
  },
  {
    from: 'buffer_overflow',
    to: 'rop_chain',
    label: 'exploited via (NX on)',
    type: 'technique',
    explanation: `When NX is enabled, the stack is not executable — you cannot run shellcode there. Instead, you reuse tiny snippets of existing code called gadgets. Each gadget ends with a ret instruction that pops the next address from the stack. By carefully arranging a series of gadget addresses on the stack, you chain them to perform arbitrary operations using only code that already exists in the binary or its libraries.`
  },
  {
    from: 'buffer_overflow',
    to: 'shellcode',
    label: 'exploited via (NX off)',
    type: 'technique',
    explanation: `When NX is disabled, the stack IS executable. You inject machine code (shellcode) directly into the buffer, then overwrite the return address to point back into the buffer where your shellcode lives. The CPU executes your code. Modern systems have NX enabled by default, making this technique rare in modern CTFs but still common in older challenges.`
  },
  {
    from: 'format_string_vuln',
    to: 'format_string',
    label: 'exploited via',
    type: 'technique',
    explanation: `A format string vulnerability lets you read or write stack values. By passing format specifiers like %p, you can dump stack pointers to bypass ASLR/PIE or leak stack canaries. By passing %n, you can write arbitrary values to any address. This provides a direct path to arbitrary memory read and write.`
  },
  {
    from: 'format_string_vuln',
    to: 'got_overwrite',
    label: 'enables',
    type: 'enable',
    explanation: `Format string bugs let you write to arbitrary locations using %n. Because the GOT is writable in binaries compiled without Full RELRO, you can use the format string vulnerability to overwrite a dynamic symbol entry (like printf) with system, making subsequent printf calls execute commands.`
  },
  {
    from: 'heap_corruption',
    to: 'heap_exploitation',
    label: 'exploited via',
    type: 'technique',
    explanation: `Heap corruption gives an attacker control over what malloc() returns. The goal in heap exploitation is almost always the same: make malloc() return an address you control so you can write to it. Common targets: The GOT table (overwrite a function pointer), the stack (write a fake return address), a function hook like __malloc_hook or __free_hook. Once malloc() returns your target address, the program writes user-controlled data there on the next operation — giving you arbitrary write.`
  },
  {
    from: 'use_after_free',
    to: 'heap_exploitation',
    label: 'exploited via',
    type: 'technique',
    explanation: `Use-After-Free (UAF) lets you interact with a freed heap chunk. If that chunk is reallocated as a different type of object, writing to the dangling pointer will corrupt the new object's fields. If the new object contains function pointers or virtual method tables, UAF lets you overwrite them and redirect control flow when they are called.`
  },
  {
    from: 'got_overwrite',
    to: 'ret2libc',
    label: 'hijacks GOT to',
    type: 'enable',
    explanation: `Overwriting a GOT entry redirects dynamic function calls. Instead of calling a standard function like printf() or puts(), the program jumps to the replacement pointer. By pointing the GOT entry of a frequently called library function directly to system() (a key libc function), you trigger command execution as soon as that function is called.`
  },

  // Col 4 to targets
  {
    from: 'nx',
    to: 'shellcode',
    label: 'blocks',
    type: 'block',
    explanation: `NX (No-Execute) marks memory regions as either executable OR writable, but never both. The stack is writable (you put data there) but not executable (the CPU refuses to execute code from there). This directly prevents shellcode injection because even if you write shellcode to the stack, the CPU will raise an exception when it tries to execute it. NX does NOT prevent ROP — because ROP reuses code in executable regions.`
  },
  {
    from: 'nx',
    to: 'rop_chain',
    label: 'makes necessary',
    type: 'force',
    explanation: `NX defeated simple shellcode injection — so attackers invented ROP. Instead of writing new code, ROP reuses existing executable code in small snippets. NX actually made exploitation more complex and interesting as a result. Each protection historically spawned a new bypass technique: NX → ROP, ASLR → info leaks, Canary → format string leaks or heap attacks. Security and attack evolve together.`
  },
  {
    from: 'pie',
    to: 'ret2win',
    label: 'complicates',
    type: 'complicate',
    explanation: `Without PIE, every function in the binary is at a fixed known address. The win() function is always at 0x401234 (or whatever it compiled to). With PIE enabled, the binary loads at a random base address each run. win() might be at 0x55abc01234 one run and 0x7f12341234 the next. To exploit ret2win with PIE, you must first leak an address from the binary (via format string or other info leak), calculate the base address offset, then add the win() function offset to get its real address.`
  },
  {
    from: 'pie',
    to: 'ret2libc',
    label: 'complicates (need leak)',
    type: 'complicate',
    explanation: `PIE randomizes the binary's address space. While ASLR randomizes the position of libc, PIE randomizes the binary itself. To perform a ret2libc, you need to call library functions. You must first find their randomized addresses in memory. This requires finding an information leak (like a format string leak) to calculate the offsets of libc functions, complicating the attack.`
  },
  {
    from: 'canary',
    to: 'buffer_overflow',
    label: 'detects',
    type: 'block',
    explanation: `A stack canary is a random value placed on the stack right before the local buffer and the return address. Before a function returns, the canary's value is checked; if it was overwritten, the program crashes immediately, preventing exploitation. Bypasses include leaking the canary value via a format string vulnerability first.`
  },
  {
    from: 'relro',
    to: 'got_overwrite',
    label: 'blocks',
    type: 'block',
    explanation: `The GOT (Global Offset Table) stores pointers to external functions like printf() and system(). Without RELRO, this table is writable — an attacker who can write an arbitrary address (via format string %n or heap primitive) can replace the pointer to printf() with the address of system(). The next call to printf() actually calls system() instead. Full RELRO makes the GOT read-only after startup, blocking this attack. Partial RELRO only protects some entries.`
  },
  {
    from: 'safe_functions',
    to: 'buffer_overflow',
    label: 'prevents',
    type: 'block',
    explanation: `Safe functions (like fgets, strncpy, and snprintf) accept a maximum buffer size parameter and stop reading or writing once that size is reached. Because they respect boundaries, they prevent data from overflowing past the allocated buffer, completely blocking standard stack and heap buffer overflows.`
  },
  {
    from: 'safe_functions',
    to: 'format_string_vuln',
    label: 'prevents',
    type: 'block',
    explanation: `Using format-safe functions or formatting strings correctly (e.g. using snprintf(buf, sizeof(buf), "%s", user_input) instead of snprintf(buf, sizeof(buf), user_input)) ensures format codes are treated as literal text. This neutralizes format string vulnerabilities by preventing users from passing active format directives to the printf family.`
  }
];

export default function RelationshipMap() {
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedConnection, setSelectedConnection] = useState(null);
  const [hoveredConnection, setHoveredConnection] = useState(null);
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 800, height: 600 });

  useEffect(() => {
    if (!containerRef.current) return;
    const updateDims = () => {
      const { offsetWidth, offsetHeight } = containerRef.current;
      if (offsetWidth > 0 && offsetHeight > 0) {
        setDims({ width: offsetWidth, height: offsetHeight });
      }
    };
    updateDims();
    window.addEventListener('resize', updateDims);
    return () => window.removeEventListener('resize', updateDims);
  }, []);

  const getNodeLeft = (node) => {
    const w = dims.width || 900;
    const colWidth = w / 4;
    return (node.col - 1) * colWidth + (colWidth - 160) / 2;
  };

  const activeNode = hoveredNode || selectedNode;

  const handleNodeClick = (nodeId) => {
    try {
      if (selectedNode === nodeId) {
        setSelectedNode(null);
      } else {
        setSelectedNode(nodeId);
        setSelectedConnection(null);
      }
    } catch (e) {
      console.error('[RelationshipMap] Click handler error:', e);
    }
  };

  const handleConnectionClick = (c) => {
    try {
      if (selectedConnection && selectedConnection.from === c.from && selectedConnection.to === c.to) {
        setSelectedConnection(null);
      } else {
        setSelectedConnection(c);
        setSelectedNode(null);
      }
    } catch (e) {
      console.error('[RelationshipMap] Connection click handler error:', e);
    }
  };

  const handleMouseEnter = (nodeId) => {
    try {
      setHoveredNode(nodeId);
    } catch (e) {
      console.error('[RelationshipMap] MouseEnter handler error:', e);
    }
  };

  const handleMouseLeave = () => {
    try {
      setHoveredNode(null);
    } catch (e) {
      console.error('[RelationshipMap] MouseLeave handler error:', e);
    }
  };

  const isNodeConnected = (nodeId) => {
    try {
      if (!activeNode) return true;
      if (nodeId === activeNode) return true;
      return (CONNECTIONS || []).some(c => 
        (c.from === activeNode && c.to === nodeId) || 
        (c.from === nodeId && c.to === activeNode)
      );
    } catch (e) {
      console.error('[RelationshipMap] isNodeConnected error:', e);
      return true;
    }
  };

  const isLineConnected = (c) => {
    try {
      if (!activeNode) return false;
      return c.from === activeNode || c.to === activeNode;
    } catch (e) {
      console.error('[RelationshipMap] isLineConnected error:', e);
      return false;
    }
  };

  const getLineColor = (type) => {
    switch (type) {
      case 'block':
        return '#f85149'; // red
      case 'force':
      case 'complicate':
        return '#e3b341'; // amber
      default:
        return '#388bfd'; // blue
    }
  };

  const activeConnections = activeNode 
    ? (CONNECTIONS || []).filter(c => c.from === activeNode || c.to === activeNode)
    : [];

  return (
    <div style={{ maxWidth: '100%', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        What Changes What: Relationship Map
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '14px',
        textAlign: 'center', marginBottom: '24px' }}>
        Hover or click a node to highlight its relations, showing how compiler choices, vulnerabilities, and protections interconnect.
      </p>
      <div style={{
        fontSize: '13px', color: '#8b949e', fontStyle: 'italic',
        textAlign: 'center', marginBottom: '16px'
      }}>
         Click any node or connection line to see a detailed explanation
      </div>

      {/* Main Diagram Area with scroll on narrow screens */}
      <div style={{ overflowX: 'auto', background: '#0d1117', border: '1px solid #30363d', borderRadius: '12px', padding: '16px', marginBottom: '24px' }}>
        <div ref={containerRef} style={{ width: '100%', height: '500px', position: 'relative', margin: '0 auto' }}>
          
          {/* SVG Overlay for Connection Lines */}
          <svg
            viewBox={`0 0 ${dims.width || 900} ${dims.height || 500}`}
            width="100%"
            height={dims.height || 500}
            style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 1 }}
          >
            {(CONNECTIONS || []).map((c, idx) => {
              const fromNode = NODES?.[c.from];
              const toNode = NODES?.[c.to];
              if (!fromNode || !toNode) return null;
              if (fromNode.left === undefined || fromNode.top === undefined || toNode.left === undefined || toNode.top === undefined) return null;

              // Compute ports based on left-to-right flow or right-to-left flow (mitigations)
              const fromCol = fromNode.col;
              const toCol = toNode.col;
              
              const fromLeft = getNodeLeft(fromNode);
              const toLeft = getNodeLeft(toNode);
              
              let startX, startY, endX, endY;
              
              if (fromCol < toCol) {
                // Left to right
                startX = fromLeft + 160;
                startY = fromNode.top + 25;
                endX = toLeft;
                endY = toNode.top + 25;
              } else {
                // Right to left (Mitigations to Vulns/Techniques)
                startX = fromLeft;
                startY = fromNode.top + 25;
                endX = toLeft + 160;
                endY = toNode.top + 25;
              }

              const controlX1 = startX + (endX - startX) * 0.4;
              const controlY1 = startY;
              const controlX2 = startX + (endX - startX) * 0.6;
              const controlY2 = endY;

              const isSelected = selectedConnection && selectedConnection.from === c.from && selectedConnection.to === c.to;
              const isHovered = hoveredConnection && hoveredConnection.from === c.from && hoveredConnection.to === c.to;
              const isHighlighted = isLineConnected(c);
              const isLineHighlighted = isHighlighted || isSelected || isHovered;

              let opacity = activeNode ? (isHighlighted ? 0.95 : 0.04) : 0.25;
              if (selectedConnection || hoveredConnection) {
                opacity = (isSelected || isHovered) ? 0.95 : 0.04;
              }

              const strokeWidth = isSelected || isHovered ? 5 : (isHighlighted ? 3 : 1.5);
              const color = getLineColor(c.type);

              return (
                <g key={idx}>
                  <path
                    d={`M ${startX} ${startY} C ${controlX1} ${controlY1}, ${controlX2} ${controlY2}, ${endX} ${endY}`}
                    fill="none"
                    stroke={color}
                    strokeWidth={strokeWidth}
                    opacity={opacity}
                    style={{ transition: 'stroke-width 0.15s, opacity 0.15s', cursor: 'pointer', pointerEvents: 'auto' }}
                    onClick={() => handleConnectionClick(c)}
                    onMouseEnter={() => setHoveredConnection(c)}
                    onMouseLeave={() => setHoveredConnection(null)}
                  />
                  {isLineHighlighted && (
                    <text
                      x={(startX + endX) / 2}
                      y={(startY + endY) / 2 - 4}
                      fill={color}
                      fontSize="9px"
                      fontFamily="monospace"
                      textAnchor="middle"
                      opacity={0.9}
                      style={{ background: '#0d1117', padding: '2px', cursor: 'pointer', pointerEvents: 'auto' }}
                      onClick={() => handleConnectionClick(c)}
                      onMouseEnter={() => setHoveredConnection(c)}
                      onMouseLeave={() => setHoveredConnection(null)}
                    >
                      {c.label}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>

          {/* Column Headers */}
          <div style={{ position: 'absolute', top: '10px', left: `${getNodeLeft({ col: 1 })}px`, width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Dangerous Functions
          </div>
          <div style={{ position: 'absolute', top: '10px', left: `${getNodeLeft({ col: 2 })}px`, width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#ff7b72', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Vulnerabilities
          </div>
          <div style={{ position: 'absolute', top: '10px', left: `${getNodeLeft({ col: 3 })}px`, width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#f0e042', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Exploit Techniques
          </div>
          <div style={{ position: 'absolute', top: '10px', left: `${getNodeLeft({ col: 4 })}px`, width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#56d364', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Mitigations
          </div>

          {/* Node Cards */}
          {(Object.values(NODES || {}) || []).map((node) => {
            if (!node) return null;
            const isConnected = isNodeConnected(node.id);
            const isMainActive = activeNode === node.id;
            const opacity = activeNode ? (isConnected ? 1.0 : 0.25) : 1.0;
            
            let colorTheme = '#30363d'; // default
            if (isMainActive) {
              colorTheme = '#58a6ff';
            } else if (node.col === 1) {
              colorTheme = '#1f242c';
            } else if (node.col === 2) {
              colorTheme = '#281515';
            } else if (node.col === 3) {
              colorTheme = '#2b2214';
            } else if (node.col === 4) {
              colorTheme = '#162c1e';
            }

            let borderTheme = '#30363d';
            if (isMainActive) {
              borderTheme = '#58a6ff';
            } else if (activeNode && isConnected) {
              borderTheme = '#8b949e';
            }

            return (
              <div
                key={node.id}
                onMouseEnter={() => handleMouseEnter(node.id)}
                onMouseLeave={() => handleMouseLeave()}
                onClick={() => handleNodeClick(node.id)}
                style={{
                  position: 'absolute',
                  left: `${getNodeLeft(node)}px`,
                  top: `${node.top}px`,
                  width: '160px',
                  height: '50px',
                  background: colorTheme,
                  border: `1px solid ${borderTheme}`,
                  borderRadius: '6px',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  cursor: 'pointer',
                  zIndex: isMainActive ? 10 : 5,
                  opacity: opacity,
                  userSelect: 'none',
                  boxShadow: isMainActive ? '0 0 10px rgba(88, 166, 255, 0.4)' : 'none',
                  transition: 'opacity 0.15s, border-color 0.15s, background-color 0.15s'
                }}
              >
                <div style={{
                  fontSize: '14px',
                  fontWeight: 600,
                  color: isMainActive ? '#fff' : '#c9d1d9',
                  textAlign: 'center',
                  fontFamily: node.col === 1 || node.col === 3 ? 'monospace' : 'inherit'
                }}>
                  {node.label}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Explanatory Details Panel */}
      <div style={{
        background: '#161b22',
        border: '1px solid #30363d',
        borderRadius: '12px',
        padding: '24px',
        minHeight: '130px',
        marginBottom: selectedConnection ? '24px' : 0
      }}>
        {activeNode && NODES?.[activeNode] ? (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {NODES[activeNode]?.label}
              </h3>
              <span style={{ fontSize: '11px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700 }}>
                Column {NODES[activeNode]?.col} Node
              </span>
            </div>
            <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6', margin: '0 0 16px' }}>
              {NODES[activeNode]?.explanation || NODES[activeNode]?.desc}
            </p>

            {/* List connections */}
            {(activeConnections || []).length > 0 && (
              <div>
                <h4 style={{ fontSize: '11px', color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 8px' }}>
                  Related Connections
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {(activeConnections || []).map((c, i) => {
                    const fromNode = NODES?.[c.from];
                    const toNode = NODES?.[c.to];
                    if (!fromNode || !toNode) return null;
                    const isFrom = c.from === activeNode;
                    const relationColor = getLineColor(c.type);

                    return (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#c9d1d9' }}>
                        <span style={{ fontWeight: 600, color: isFrom ? '#58a6ff' : '#8b949e' }}>
                          {fromNode?.label}
                        </span>
                        <span style={{
                          fontSize: '10px',
                          padding: '1px 6px',
                          borderRadius: '4px',
                          background: relationColor + '20',
                          border: `1px solid ${relationColor}`,
                          color: relationColor,
                          fontWeight: 700
                        }}>
                          {c.label}
                        </span>
                        <span style={{ fontWeight: 600, color: !isFrom ? '#58a6ff' : '#8b949e' }}>
                          {toNode.label}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80px', color: '#8b949e', fontSize: '14px' }}>
             Click or hover any block in the map to discover its compiler, vulnerability, and exploit paths.
          </div>
        )}
      </div>

      {/* Selected Connection Explanation Panel */}
      {selectedConnection && (
        <div style={{
          marginTop: '24px', padding: '20px',
          background: '#161b22', borderRadius: '8px',
          border: '1px solid #30363d'
        }}>
          <div style={{
            display: 'flex', justifyContent: 'space-between',
            alignItems: 'flex-start', marginBottom: '12px'
          }}>
            <div style={{ fontSize: '14px', fontWeight: 600, color: '#c9d1d9' }}>
              {NODES[selectedConnection.from]?.label || selectedConnection.from} → {NODES[selectedConnection.to]?.label || selectedConnection.to}
              <span style={{
                marginLeft: '8px', fontSize: '11px',
                color: getLineColor(selectedConnection.type),
                textTransform: 'uppercase',
                padding: '1px 6px',
                borderRadius: '4px',
                background: getLineColor(selectedConnection.type) + '20',
                border: `1px solid ${getLineColor(selectedConnection.type)}`
              }}>
                {selectedConnection.label}
              </span>
            </div>
            <button
              onClick={() => setSelectedConnection(null)}
              style={{
                background: 'none', border: 'none',
                color: '#6e7681', fontSize: '18px', cursor: 'pointer'
              }}
            >✕</button>
          </div>
          <p style={{
            color: '#c9d1d9', fontSize: '14px',
            lineHeight: '1.7', margin: 0,
            whiteSpace: 'pre-line'
          }}>
            {selectedConnection.explanation}
          </p>
        </div>
      )}
    </div>
  );
}
