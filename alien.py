# alien.py
# Driver code 
import sys

from pe_parser import load_pe, get_basic_info, get_executable_sections
from disasm import disassemble_bytes
from matcher import match_all_rules


if len(sys.argv) != 2: #ensure a sample is provided
    print(f"Usage: python {sys.argv[0]} <sample.exe>")
    sys.exit(1)


pe = load_pe(sys.argv[1]) # load the PE file and parse its structure
info = get_basic_info(pe) # get basic info like architecture, image base, entry point, etc.

architecture = info["architecture"]
image_base = info["image_base"]
entry_va = info["entry_point_va"]

all_findings = []

for section in get_executable_sections(pe): #iterate through executable sections to find entry point and disassemble
    section_va = image_base + section["virtual_address"]
    section_end = section_va + section["raw_size"]

    if section_va <= entry_va < section_end:
        offset = entry_va - section_va
        code = section["raw_data"][offset:offset + 1024]
        start_address = entry_va
    else:
        code = section["raw_data"][:1024]
        start_address = section_va

    instructions = disassemble_bytes(
        code_bytes=code,
        start_address=start_address,
        architecture=architecture,
        max_instructions=200
    )

    findings = match_all_rules(instructions) # apply all matching rules to the disassembled instructions
    all_findings.extend(findings)


# Print results
print("Alien Analyzer - Anti-Analysis Signature Detection")
print("===============================================")
print(f"Sample: {sys.argv[1]}")
print(f"Architecture: {architecture}")
print(f"Image Base: 0x{image_base:X}")
print(f"Entry Point: 0x{entry_va:X}")
print() 

visible_findings = []

for finding in all_findings:
    if finding["category"] != "info":
        visible_findings.append(finding)
        

if not visible_findings:
    print("No suspicious anti-analysis signatures found.")
else:
    for finding in visible_findings:
        print(f"0x{finding['address']:X}: {finding['instruction']}")
        print(f"  Rule: {finding['rule_name']}")
        print(f"  Category: {finding['category']}")
        print(f"  Reason: {finding['description']}")
        print()