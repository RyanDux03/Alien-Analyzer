# Alien Analyzer

Alien Analyzer is a static malware analysis tool for Windows PE files that detects anti-debugging and anti-virtual machine techniques.

The tool disassembles executable sections and applies rule-based detection to identify behaviors commonly used by malware to evade analysis.

---

## Features

- PE file parsing using `pefile`
- Disassembly using Capstone
- Detection of anti-debugging techniques:
  - PEB BeingDebugged checks
  - INT3 usage (with padding filtering)
  - Debug-related API imports (e.g., `IsDebuggerPresent`)
- Detection of anti-VM techniques:
  - CPUID usage
  - Firmware and network-based checks
- Import-based and instruction-based analysis
- Noise filtering for compiler padding
- Suspicion scoring with final verdict

---

## Usage

Download `alien.exe` and run:

```bat
alien.exe sample.exe
```

## Example Output

```text
0x1400019B0: mov rax, gs:[0x60] -> mov al, [rax+2]
  Rule: PEB BeingDebugged check
  Category: anti_debug
  Severity: 5
  Reason: Likely debugger detection via PEB BeingDebugged flag.

kernel32.dll!isdebuggerpresent
  Rule: IsDebuggerPresent
  Category: anti_debug
  Severity: 3
  Reason: Checks for debugger presence.

Overall Suspicion Score: 8
Verdict: Moderate suspicion

```

## Requirements
If running from source:
* Python 3.8
* pefile
* capstone
Install with:
```bat
pip install -r requirements.txt
```

## Safety Notice
This tool performs static analysis only and does not execute the input file.

## Future Work
* Expand rule set
* Improve sequence based matching
* Add patching functionality

## Author
Ryan Duxstad

