# rules.py

# name, category, mnemonic, severity (1-4), description

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

IMPORT_RULES = [
    {
        "name": "IsDebuggerPresent",
        "category": "anti_debug",
        "function": "isdebuggerpresent",
        "severity": 3,
        "description": "Checks for debugger presence."
    },
    {
        "name": "CheckRemoteDebuggerPresent",
        "category": "anti_debug",
        "function": "checkremotedebuggerpresent",
        "severity": 4,
        "description": "Checks for remote debugger."
    },
    {
        "name": "NtQueryInformationProcess",
        "category": "anti_debug",
        "function": "ntqueryinformationprocess",
        "severity": 4,
        "description": "Can detect debug flags or ports."
    },

    {
        "name": "GetSystemFirmwareTable",
        "category": "anti_vm",
        "function": "getsystemfirmwaretable",
        "severity": 3,
        "description": "Used to inspect BIOS/firmware (VM detection)."
    },
    {
        "name": "GetAdaptersInfo",
        "category": "anti_vm",
        "function": "getadaptersinfo",
        "severity": 3,
        "description": "Used to check MAC addresses for VM vendors."
    },
]