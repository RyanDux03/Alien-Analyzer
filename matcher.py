# matcher.py

from rules import SINGLE_INSTRUCTION_RULES, OPERAND_CONTAINS_RULES


def match_single_instruction_rules(instructions):
    findings = []

    i = 0
    while i < len(instructions):
        insn = instructions[i]

        # Handle standard int3 instructions
        if insn["mnemonic"] == "int3":
            start = i

            while i < len(instructions) and instructions[i]["mnemonic"] == "int3":
                i += 1

            count = i - start

            if count <= 2:
                for j in range(start, i):
                    findings.append({
                        "address": instructions[j]["address"],
                        "instruction": "int3",
                        "rule_name": "Software breakpoint",
                        "category": "anti_debug",
                        "severity": 1,
                        "description": "Single INT3 may indicate breakpoint or anti-debugging."
                    })
            else:
                findings.append({
                    "address": instructions[start]["address"],
                    "instruction": f"{count} consecutive int3",
                    "rule_name": "Padding (ignored)",
                    "category": "info",
                    "severity": 0,
                    "description": f"Likely compiler padding ({count} INT3 instructions)."
                })

            continue

        # Normal single-instruction rules
        for rule in SINGLE_INSTRUCTION_RULES:
            if insn["mnemonic"] == rule["mnemonic"] and insn["mnemonic"] != "int3":
                findings.append({
                    "address": insn["address"],
                    "instruction": f"{insn['mnemonic']} {insn['op_str']}".strip(),
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "description": rule["description"]
                })

        i += 1

    return findings


def match_operand_rules(instructions):  
    findings = []

    for insn in instructions:
        op_str = insn["op_str"].replace(" ", "")

        for rule in OPERAND_CONTAINS_RULES:
            target = rule["operand_substring"].replace(" ", "")

            if target in op_str:
                findings.append({
                    "address": insn["address"],
                    "instruction": f"{insn['mnemonic']} {insn['op_str']}".strip(),
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "description": rule["description"]
                })

    return findings

def match_peb_being_debugged(instructions):
    findings = []

    for i in range(len(instructions) - 1):
        insn1 = instructions[i]
        insn2 = instructions[i + 1]

        # Normalize operands
        op1 = insn1["op_str"].replace(" ", "")
        op2 = insn2["op_str"].replace(" ", "")

        # Step 1: detect PEB load
        if "gs:[0x60]" in op1 or "fs:[0x30]" in op1:
            
            # Step 2: check for access to +2 offset (BeingDebugged)
            if "+2]" in op2:
                findings.append({
                    "address": insn1["address"],
                    "instruction": f"{insn1['mnemonic']} {insn1['op_str']} -> {insn2['mnemonic']} {insn2['op_str']}",
                    "rule_name": "PEB BeingDebugged check",
                    "category": "anti_debug",
                    "severity": 5,
                    "description": "Likely debugger detection via PEB BeingDebugged flag."
                })

    return findings


def match_all_rules(instructions):
    findings = []

    findings.extend(match_single_instruction_rules(instructions))
    findings.extend(match_operand_rules(instructions))
    findings.extend(match_peb_being_debugged(instructions))

    return findings

