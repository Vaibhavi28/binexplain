export const TOOL_INSTALL_COMMANDS = {
  "gdb":        "sudo apt-get install -y gdb",
  "pwndbg":     "git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh",
  "gef":        "bash -c \"$(wget -O- https://gef.blah.cat/sh)\"",
  "checksec":   "pip3 install checksec.py",
  "ROPgadget":  "pip3 install ROPgadget",
  "ropper":     "pip3 install ropper",
  "pwntools":   "pip3 install pwntools",
  "objdump":    "sudo apt-get install -y binutils",
  "readelf":    "sudo apt-get install -y binutils",
  "strings":    "sudo apt-get install -y binutils",
  "ltrace":     "sudo apt-get install -y ltrace",
  "strace":     "sudo apt-get install -y strace",
  "radare2":    "sudo apt-get install -y radare2",
  "r2":         "sudo apt-get install -y radare2",
  "nm":         "sudo apt-get install -y binutils",
  "ldd":        "sudo apt-get install -y libc-bin",
  "binwalk":    "pip3 install binwalk",
  "one_gadget": "gem install one_gadget",
  "angr":       "pip3 install angr",
  "patchelf":   "sudo apt-get install -y patchelf",
  "cyclic":     "pip3 install pwntools",
};

export const detectToolInCommand = (command) => {
  if (!command) return null;
  const cmdLower = command.toLowerCase().trim();
  // Remove common prefixes before checking
  const stripped = cmdLower
    .replace(/^sudo\s+/, '')
    .replace(/^python3?\s+-[mc]\s+/, '')
    .replace(/^\.\//, '');

  for (const [tool, installCmd] of Object.entries(TOOL_INSTALL_COMMANDS)) {
    if (
      stripped.startsWith(tool.toLowerCase()) ||
      stripped.startsWith(tool.toLowerCase() + ' ') ||
      stripped.includes(' ' + tool.toLowerCase() + ' ')
    ) {
      return { tool, installCmd };
    }
  }
  return null;
};
