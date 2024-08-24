import struct 
import math

PE_HEADER_OFFSET = 60
PE_HEADER_OFFSET_LENGTH = 4

PE_MAGIC_LENGTH = 4
OPT_HEADER_MAGIC_LENGTH = 2
COFF_LENGTH = 20
COFF_N_SECTION = 2

DLL_CHARACTERISTICS_OFFSET_FROM_PE = 70
DLL_CHARACTERISTICS_LENGTH = 2

SECTION_EXECUTABLE = 0x80000000

DYNAMIC_REBASE =    0x0040
FORCE_INTEGRITY =   0x0080

SECTION_ENTRY_LENGTH = 40

def align(value, align_on):
    r = value % align_on
    if r > 0:
        return value + (align_on - r)
    return value


class Binary:
    def __init__(self, path=None, bytez=None):
        if path is None and bytez is None:
            raise ValueError("You must pass as input either a path or bytes")
        self.exe_bytes = bytearray()
        if path is not None:
            with open(path, 'rb') as f:
                self.exe_bytes = bytearray(f.read())
        else:
            self.exe_bytes = bytearray(bytez)

    @classmethod
    def load_from_path(cls, path : str):
        return cls(path=path)
    
    @classmethod
    def load_from_bytes(cls, bytez : bytearray):
        return cls(bytez=bytez)

    @staticmethod
    def flag_is_on(characteristics, flag):
        return (characteristics & flag) == flag

    @staticmethod
    def deactivate_flag(characteristics, flag):
        if Binary.flag_is_on(characteristics, flag):
            characteristics &= ~flag
        return characteristics

    @staticmethod
    def activate_flag(characteristics, flag):
        if not Binary.flag_is_on(characteristics, flag):
            characteristics |= flag
        return characteristics

    def get_bytes(self):
        return self.exe_bytes

    def get_pe_location(self):
        pe_location = self.exe_bytes[PE_HEADER_OFFSET:PE_HEADER_OFFSET+PE_HEADER_OFFSET_LENGTH]
        return int.from_bytes(pe_location, 'little')

    def get_optional_header_location(self):
        pe_location = self.get_pe_location()
        optional_header_location = pe_location + PE_MAGIC_LENGTH + 20
        return optional_header_location

    def get_optional_header_size(self):
        pe_location = self.get_pe_location()
        size_opt_header_location = pe_location + PE_MAGIC_LENGTH + 16
        size_opt_header = self.exe_bytes[size_opt_header_location: size_opt_header_location + 2]
        size_opt_header = int.from_bytes(size_opt_header, 'little')
        return size_opt_header

    def get_section_table_location(self):
        size_opt_header = self.get_optional_header_size()
        return self.get_optional_header_location() + size_opt_header

    def patch_aslr(self):
        pe_location = self.get_pe_location()
        dll_location = pe_location + DLL_CHARACTERISTICS_OFFSET_FROM_PE + COFF_LENGTH + PE_MAGIC_LENGTH # COFF and PE length

        characteristics = self.exe_bytes[dll_location : dll_location + DLL_CHARACTERISTICS_LENGTH]
        characteristics = int.from_bytes(characteristics, 'little')
        new_characteristics = Binary.deactivate_flag(characteristics, DYNAMIC_REBASE)
        new_characteristics = Binary.deactivate_flag(new_characteristics, FORCE_INTEGRITY)

        new_characteristics = new_characteristics.to_bytes(2, 'little')
        self.exe_bytes[dll_location : dll_location + DLL_CHARACTERISTICS_LENGTH] = new_characteristics
        return self.exe_bytes

    def get_total_number_sections(self):
        pe_location = self.get_pe_location()
        n_sections = self.exe_bytes[pe_location + PE_MAGIC_LENGTH + COFF_N_SECTION : pe_location + PE_MAGIC_LENGTH + COFF_N_SECTION + 2]
        n_sections = int.from_bytes(n_sections, 'little')
        return n_sections
    
    def increase_number_sections(self):
        pe_location = self.get_pe_location()
        n_sections = self.exe_bytes[pe_location + PE_MAGIC_LENGTH + COFF_N_SECTION : pe_location + PE_MAGIC_LENGTH + COFF_N_SECTION + 2]
        n_sections = int.from_bytes(n_sections, 'little') + 1
        self.exe_bytes[pe_location + PE_MAGIC_LENGTH + COFF_N_SECTION : pe_location + PE_MAGIC_LENGTH + COFF_N_SECTION + 2] = n_sections.to_bytes(2, 'little')

    def get_section_entry_location_from_index(self, index: int):
        n_sections = self.get_total_number_sections()
        if index > n_sections:
            raise ValueError(f"Section with index {index} not found. Only {n_sections} are present.")
        section_table_offset = self.get_section_table_location()
        return section_table_offset + index*40

    def get_section_entry_from_index(self, index: int):
        n_sections = self.get_total_number_sections()
        if index > n_sections:
            raise ValueError(f"Section with index {index} not found. Only {n_sections} are present.")
        section_table_offset = self.get_section_table_location()
        return self.exe_bytes[section_table_offset + index*40 : section_table_offset + (index+1)*40]

    def make_section_writable(self, section_name : str):
        n_sections = self.get_total_number_sections()
        section_table_offset = self.get_section_table_location()
        for i in range(n_sections):
            current_offset = section_table_offset + i*SECTION_ENTRY_LENGTH
            name = self.exe_bytes[current_offset : current_offset + 8]
            name = name.decode()
            if section_name in name:
                print(f"Found {section_name} in binary")
                section_characteristics = self.exe_bytes[current_offset + 36 : current_offset + 40]
                section_characteristics = int.from_bytes(section_characteristics, 'little')
                writable_section_characteristics = Binary.activate_flag(section_characteristics, SECTION_EXECUTABLE)
                self.exe_bytes[current_offset + 36 : current_offset + 40] = writable_section_characteristics.to_bytes(4, 'little')
                break
        return self.exe_bytes

    def get_section_alignment(self):
        optional_header_location = self.get_optional_header_location()
        section_alignment = int.from_bytes(self.exe_bytes[optional_header_location + 32: optional_header_location + 32 + 4], 'little')
        return section_alignment
    
    def get_file_alignment(self):
        optional_header_location = self.get_optional_header_location()
        file_alignment = int.from_bytes(self.exe_bytes[optional_header_location + 36: optional_header_location + 36 + 4], 'little')
        return file_alignment

    def get_sizeof_headers(self):
        optional_header_location = self.get_optional_header_location()
        sizeof_headers = int.from_bytes(self.exe_bytes[optional_header_location + 60: optional_header_location + 60 + 4],'little')
        return sizeof_headers # multiple of FileAlignment
    
    def set_sizeof_headers(self, value:int):
        optional_header_location = self.get_optional_header_location()
        self.exe_bytes[optional_header_location + 60: optional_header_location + 60 + 4:] = value.to_bytes(4, 'little')
        return value # multiple of FileAlignment

    def get_sizeof_image(self):
        optional_header_location = self.get_optional_header_location()
        sizeof_image = int.from_bytes(self.exe_bytes[optional_header_location + 56: optional_header_location + 56 + 4], 'little')
        return sizeof_image # multiple of SectionAlignment
    
    def set_sizeof_image(self, value:int):
        optional_header_location = self.get_optional_header_location()
        self.exe_bytes[optional_header_location + 56: optional_header_location + 56 + 4:] = value.to_bytes(4,'little')

    def increase_pointer_raw_section(self, section_index:int, value:int):
        section_table_offset = self.get_section_table_location() + section_index * 40
        old_pointer = int.from_bytes(self.exe_bytes[section_table_offset + 20: section_table_offset + 20 + 4], 'little')
        new_pointer = old_pointer + value
        self.exe_bytes[section_table_offset + 20: section_table_offset + 20 + 4] = new_pointer.to_bytes(4, 'little')

    def add_section(self, name:str, characteristics:int, content:bytearray):
        n_sections = self.get_total_number_sections()

        last_section = self.get_section_entry_from_index(n_sections - 1)
        last_virtual_address = int.from_bytes(last_section[12 : 12 + 4], 'little')
        last_virtual_size = int.from_bytes(last_section[8 : 8 + 4], 'little')
        last_raw_size = int.from_bytes(last_section[16 : 16 + 4], 'little')
        last_pointer_raw = int.from_bytes(last_section[20 : 20 + 4], 'little')

        section_alignment = self.get_section_alignment()
        file_alignment = self.get_file_alignment()

        next_virtual_address = align(last_virtual_size, section_alignment)
        next_virtual_address = next_virtual_address + last_virtual_address

        size_rawdata = align(len(content), file_alignment)

        # create section entry ✅
        new_section_entry = bytearray([0]*40)
        str_len = min(len(name), 8)
        new_section_entry[0 : str_len] = bytearray(name[:str_len], 'ascii')         # name of section
        new_section_entry[8 : 8 + 4] = len(content).to_bytes(4, 'little')           # virtual size
        new_section_entry[12 : 12 + 4] = next_virtual_address.to_bytes(4, 'little') # virtual address
        new_section_entry[16 : 16 + 4] = size_rawdata.to_bytes(4, 'little')         # size fo raw data
        new_section_entry[20 : 20 + 4] = (0).to_bytes(4, 'little')                  # pointer to content in file (null now)
        new_section_entry[36 : 36 + 4] = characteristics.to_bytes(4, 'little')      # characteristics of section

        old_sizeof_headers = self.get_sizeof_headers()

        # increase size of headers ✅
        new_sizeof_headers = self.get_section_table_location() + (n_sections+1) * 40
        section_table_offset = self.get_section_table_location()
        where_to_insert_entry = section_table_offset + n_sections * 40
        where_to_insert_content = last_pointer_raw + last_raw_size
        increment_image_size = 0
        if new_sizeof_headers >= old_sizeof_headers:
            # modify SizeOfHeaders to include 40bytes (aligned to FileAlignment) ✅
            increment = align(SECTION_ENTRY_LENGTH, file_alignment)
            self.exe_bytes = self.exe_bytes[:where_to_insert_entry] + b'\x00' * increment + self.exe_bytes[where_to_insert_entry:]
            self.set_sizeof_headers(old_sizeof_headers + increment)
            where_to_insert_content = where_to_insert_content + increment
            increment_image_size = increment
            # if not enough space, add FileAlignment, displace all pointers to raw data by FileAlignment ✅
            for i in range(n_sections):
                self.increase_pointer_raw_section(i, increment)
        
        # add new entry to section table ✅
        new_section_entry[20 : 20 + 4] = where_to_insert_content.to_bytes(4, 'little')  # pointer to content in file
        self.exe_bytes[where_to_insert_entry : where_to_insert_entry + 40] = new_section_entry

        # add content at the end, beware the overlay ✅
        self.exe_bytes = self.exe_bytes[:where_to_insert_content] + b'\x00' * size_rawdata + self.exe_bytes[where_to_insert_content:]
        self.exe_bytes[where_to_insert_content : where_to_insert_content + len(content)] = content
        
        # modify SizeOfImage accordingly, multiple of SectionAlignment ✅
        padded_virtual_size = align(len(content) + increment_image_size, section_alignment)
        self.set_sizeof_image(self.get_sizeof_image() + padded_virtual_size)

        # increase number of sections ✅
        self.increase_number_sections()
        return self.exe_bytes
    
    def extend_dos_header(self, size: int):
        # BEWARE: extending too much will cause the header to shift also the text section ✅
        # Not possible with current editing
        first_section = self.get_section_entry_from_index(0)
        first_va = int.from_bytes(first_section[12:16], 'little')
        increment = align(size, self.get_file_alignment())
        if self.get_sizeof_headers() + increment > first_va:
            print("Not enough space to increase header, first section would need displacement in RAM.")
            print(f"Minimum increment: {increment}")
            print(f"Available space: {first_va - self.get_sizeof_headers()}")
        # shift all section content pointers by size, aligned to FileAlignment ✅
        for i in range(self.get_total_number_sections()):
            self.increase_pointer_raw_section(i, increment)
        # increase size of headers ✅
        self.set_sizeof_headers(self.get_sizeof_headers() + increment)
        pe_location = self.get_pe_location()
        self.exe_bytes = self.exe_bytes[:pe_location] + b"\x00"*increment + self.exe_bytes[pe_location:]
        # increase offset of PE header✅
        self.exe_bytes[PE_HEADER_OFFSET:PE_HEADER_OFFSET+PE_HEADER_OFFSET_LENGTH] = (pe_location+increment).to_bytes(4, 'little')

    def displace_section_by(self, section_index:int, size: int):
        # Add zero bytes BEFORE the specified section ✅
        increment = align(size, self.get_file_alignment())
        entry = self.get_section_entry_from_index(section_index)
        location = int.from_bytes(entry[20 : 24], 'little')
        self.exe_bytes = self.exe_bytes[:location] + b"\x00" * increment + self.exe_bytes[location:]
        # shift all section content pointers by size, aligned to FileAlignment ✅
        for i in range(section_index, self.get_total_number_sections()):
            self.increase_pointer_raw_section(i, increment)

    def add_print_before_execution(self):
        old_absolute_entry_point = 0x140001820
        shellcode = f"""
        sub rsp, 32;
        mov rax, 0x6f6c6c6568000000;
        mov [rsp + 16], rax;
        mov rax, 0x0000000000000000;
        mov [rsp + 8], rax;
        mov rax, 0x0000000000000008;
        mov rcx, -11;
        xor rdx, rdx;
        xor r8, r8;
        xor r9, r9;
        lea r10, [rsp + 8];
        lea r8, [rsp + 16];
        mov r9d, 5;
        syscall;
        mov rax, {old_absolute_entry_point}
        push rax;
        xor rax, rax;
        ret;
        """
        from keystone import Ks, KS_ARCH_X86, KS_MODE_64
        engine = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, _ = engine.asm(shellcode)
        assembled_shellcode = b"".join([a.to_bytes(1, 'little') for a in encoding])
        text_entry = self.get_section_entry_from_index(0)
        virtual_size = int.from_bytes(text_entry[8:12], 'little')
        virtual_address = int.from_bytes(text_entry[12:16], 'little')
        raw_offset = int.from_bytes(text_entry[20:24], 'little')
        print(len(self.exe_bytes))
        self.exe_bytes[raw_offset + virtual_size : raw_offset + virtual_size + len(assembled_shellcode)] = assembled_shellcode
        print(len(self.exe_bytes))
        new_entry_point =  virtual_size + virtual_address
        optional_header_location = self.get_optional_header_location()
        entry_point = int.from_bytes(self.exe_bytes[optional_header_location + 16 : optional_header_location + 20], 'little')
        print(f"OLD ENTRY POINT: {entry_point}")
        print(f"NEW ENTRY POINT: {new_entry_point}")
        self.exe_bytes[optional_header_location + 16 : optional_header_location + 20] = new_entry_point.to_bytes(4, 'little')




if __name__ == '__main__':
    calc = Binary.load_from_path("calc.exe")
    calc.patch_aslr()
    calc.add_print_before_execution()
    with open("printto_calc.exe", "wb") as f:
        f.write(calc.get_bytes())