# pe_parser.py
import pefile

IMAGE_SCN_MEM_EXECUTE = 0x20000000


def load_pe(path):
    """
    Load and parse a PE file.
    """
    return pefile.PE(path)


def get_architecture(pe):
    """
    Return x86, x64, or unknown.
    """
    machine = pe.FILE_HEADER.Machine

    if machine == 0x14C:
        return "x86"
    elif machine == 0x8664:
        return "x64"
    else:
        return f"unknown_0x{machine:04x}"


def get_image_base(pe):
    return pe.OPTIONAL_HEADER.ImageBase


def get_entry_point_rva(pe):
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint


def get_entry_point_va(pe):
    return get_image_base(pe) + get_entry_point_rva(pe)


def get_section_name(section):
    return section.Name.decode(errors="ignore").rstrip("\x00")


def is_executable_section(section):
    return bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)


def get_executable_sections(pe):
    """
    Return all sections marked executable.
    """
    sections = []

    for section in pe.sections:
        if is_executable_section(section):
            sections.append({
                "name": get_section_name(section),
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "raw_data": section.get_data(),
                "entropy": section.get_entropy(),
                "characteristics": section.Characteristics
            })

    return sections


def get_basic_info(pe):
    """
    Return basic PE metadata for reporting/debugging.
    """
    return {
        "architecture": get_architecture(pe),
        "image_base": get_image_base(pe),
        "entry_point_rva": get_entry_point_rva(pe),
        "entry_point_va": get_entry_point_va(pe),
        "number_of_sections": pe.FILE_HEADER.NumberOfSections
    }
    
def get_imports(pe):
    imports = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="ignore").lower()

        for imp in entry.imports:
            if imp.name:
                func = imp.name.decode(errors="ignore").lower()
                addr = imp.address
                imports.append({
                    "dll": dll,
                    "function": func,
                    "address": addr
                })

    return imports