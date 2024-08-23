import lief
from pe_binary import Binary

SECTION_LENGTH = 512

def get_section_offset(exe_binary : Binary):
    entry = exe_binary.get_section_entry_from_index(0)
    return int.from_bytes(entry[20:24], 'little')

def compare_section_creation(pebinary: lief.PE.Binary, binary:Binary):
    section = lief.PE.Section(".test")
    section.content = [41] * SECTION_LENGTH
    section.characteristics = 0x60000020
    pebinary.add_section(section)
    builder = lief.PE.Builder(pebinary)
    builder.build()

    binary.add_section(".test", 0x60000020, b"\x41" * SECTION_LENGTH)

    exe_lief = builder.get_build()
    exe_lief = Binary(bytez=exe_lief)
    print(f"Adding {i+1} section")
    print("Start txt section.")
    print("LIEF:", get_section_offset(exe_lief))
    print("NATV:", get_section_offset(binary))
    print("Size of Headers")
    print("LIEF:", exe_lief.get_sizeof_headers())
    print("NATV:", binary.get_sizeof_headers())
    print("-_-_"*10)

UPPER_LIMIT = 40
PATH = "calc.exe"
pebinary = lief.PE.parse(PATH)
calc = Binary(path=PATH)
for i in range(UPPER_LIMIT):
    compare_section_creation(pebinary, calc)