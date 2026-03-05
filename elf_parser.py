from dataclasses import dataclass
from enum import IntEnum
from struct import unpack, pack

# ==================== ELF 상수 정의 ====================

class ELFClass(IntEnum):
    """ELF 클래스 (32/64비트)"""
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2

class ELFData(IntEnum):
    """데이터 인코딩 (엔디안)"""
    ELFDATANONE = 0
    ELFDATA2LSB = 1  # Little Endian
    ELFDATA2MSB = 2  # Big Endian

# ==================== 데이터 클래스 ====================

@dataclass
class ELFHeader:
    """ELF 헤더 정보"""
    ei_class: int        # 32/64비트
    ei_data: int         # 엔디안
    ei_version: int      # ELF 버전
    ei_osabi: int        # OS/ABI
    ei_abiversion: int   # ABI 버전
    e_type: int          # 파일 타입
    e_machine: int       # 아키텍처
    e_version: int       # 버전
    e_entry: int         # 엔트리 포인트
    e_phoff: int         # Program header offset
    e_shoff: int         # Section header offset
    e_flags: int         # 프로세서 플래그
    e_ehsize: int        # ELF 헤더 크기
    e_phentsize: int     # Program header 엔트리 크기
    e_phnum: int         # Program header 개수
    e_shentsize: int     # Section header 엔트리 크기
    e_shnum: int         # Section header 개수
    e_shstrndx: int      # Section name string table index

@dataclass
class ProgramHeader:
    '''Program Header 정보'''
    p_type: int
    p_flag: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


class ELFParser:
    ELF_MAGIC = b'\x7fELF'

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.elf_header = None
        self.program_headers = []
        self.section_headers = []
        with open(self.file_path, 'rb') as f:
            self.data = f.read()

    def parse(self):
        # ELF 파일 파싱 로직 구현
        if self.parse_elf_header():
            print("--- ELF Header parsed successfully! ---")
            print(self.elf_header)
        if self.parse_program_header():
            print("--- ProgramHeader parsed successfully! ---")
            print(self.program_headers)

    def parse_elf_header(self) -> bool:
        # ELF 헤더 파싱 로직 구현
        if self.data[0:4] != self.ELF_MAGIC:
            return False
        
        # e_ident 파싱 (처음 16바이트)
        ei_class = self.data[4]
        ei_data = self.data[5]
        ei_version = self.data[6]
        ei_osabi = self.data[7]
        ei_abiversion = self.data[8]

        self.is_64bit = (ei_class == ELFClass.ELFCLASS64)
        self.is_little_endian = (ei_data == ELFData.ELFDATA2LSB)

        if self.is_64bit:
            # ELF64 헤더 (64바이트)
            if len(self.data) < 64:
                return False
            
            header_format = '<HHIQQQIHHHHHH' if self.is_little_endian else '>HHIQQQIHHHHHH'
            unpacked = unpack(header_format, self.data[16:64])
            self.elf_header = ELFHeader(
                ei_class=ei_class,
                ei_data=ei_data,
                ei_version=ei_version,
                ei_osabi=ei_osabi,
                ei_abiversion=ei_abiversion,
                e_type=unpacked[0],
                e_machine=unpacked[1],
                e_version=unpacked[2],
                e_entry=unpacked[3],
                e_phoff=unpacked[4],
                e_shoff=unpacked[5],
                e_flags=unpacked[6],
                e_ehsize=unpacked[7],
                e_phentsize=unpacked[8],
                e_phnum=unpacked[9],
                e_shentsize=unpacked[10],
                e_shnum=unpacked[11],
                e_shstrndx=unpacked[12]
            )
        else:
            return False  # ELF32는 지원하지 않음
        return True
            
    def parse_program_header(self) -> bool:
        # 64bit 기준
        for idx in range(0, self.elf_header.e_phnum):
            binary_ph = self.data[self.elf_header.e_phoff + idx*self.elf_header.e_phentsize: self.elf_header.e_phoff + (idx+1)*self.elf_header.e_phentsize]
            unpacked = unpack('<IIQQQQQQ', binary_ph)
            ph = ProgramHeader(
                p_type=unpacked[0],
                p_flag=unpacked[1],
                p_offset=unpacked[2],
                p_vaddr=unpacked[3],
                p_paddr=unpacked[4],
                p_filesz=unpacked[5],
                p_memsz=unpacked[6],
                p_align=unpacked[7]
            )
            self.program_headers.append(ph)
        return True

