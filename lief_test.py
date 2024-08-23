import lief
from zangope import Binary
import time
lief.logging.enable()
lief.logging.set_level(lief.logging.LOGGING_LEVEL.TRACE)
lief.logging.set_path("lief.log.txt")

start_t = time.time()
SCTS = 88
SECTION_LENGHT = 512
pebinary = lief.PE.parse("calc.exe")
for i in range(SCTS):
    section = lief.PE.Section(".test")
    section.content = [41] * SECTION_LENGHT
    section.characteristics = 0x60000020
    pebinary.add_section(section)
builder = lief.PE.Builder(pebinary)
builder.build()
end_t = time.time()
builder.write("lief_calc.exe")
print(f"Created LIEF version, took {end_t - start_t}")

start_t = time.time()
with open("calc.exe", "rb") as f:
    calc_bytes = bytearray(f.read())
calc = Binary(bytez=calc_bytes)
for i in range(SCTS):
    calc_bytes = calc.add_section(".test", 0x60000020, b"\x41" * SECTION_LENGHT)
end_t = time.time()
with open("addsect_calc.exe", "wb") as f:
    f.write(calc_bytes)
print(f"Created NATIVE version, took {end_t - start_t}")