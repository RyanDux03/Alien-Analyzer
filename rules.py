# rules.py

# name, category, mnemonic, severity (1-3), description

SINGLE_INSTRUCTION_RULES = [
    {
        "name": "RDTSC timing check",
        "category": "anti_debug",
        "mnemonic": "rdtsc",
        "severity": 2,
        "description": "RDTSC can be used for timing-based anti-debugging checks."
    },
    {
        "name": "CPUID instruction",
        "category": "anti_vm",
        "mnemonic": "cpuid",
        "severity": 2,
        "description": "CPUID can be used to detect virtualization or hypervisors."
    },
    {
        "name": "Software breakpoint",
        "category": "anti_debug",
        "mnemonic": "int3",
        "severity": 1,
        "description": "INT3 is a software breakpoint instruction. Long runs may simply be padding."
    },
]

OPERAND_CONTAINS_RULES = [
    {
        "name": "x86 PEB access",
        "category": "anti_debug",
        "mnemonic": None,
        "operand_substring": "fs:[0x30]",
        "severity": 3,
        "description": "Access to fs:[0x30] may indicate x86 PEB access for anti-debugging."
    },
    {
        "name": "x64 PEB access",
        "category": "anti_debug",
        "mnemonic": None,
        "operand_substring": "gs:[0x60]",
        "severity": 3,
        "description": "Access to gs:[0x60] may indicate x64 PEB access for anti-debugging."
    },
]