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

class ProgramHeaderType(IntEnum):
    """Program Header 타입"""
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6

class DynamicTag(IntEnum):
    """Dynamic 엔트리 태그 (ELF 표준 + GNU/Android 확장)"""
    
    # === 표준 ELF 태그 (0-24) ===
    DT_NULL = 0          # 동적 섹션 끝 표시
    DT_NEEDED = 1        # 필요한 공유 라이브러리 이름 (strtab 오프셋)
    DT_PLTRELSZ = 2      # PLT relocation 테이블 크기
    DT_PLTGOT = 3        # PLT/GOT 주소
    DT_HASH = 4          # 심볼 해시 테이블 주소
    DT_STRTAB = 5        # 문자열 테이블(.dynstr) 주소
    DT_SYMTAB = 6        # 심볼 테이블(.dynsym) 주소
    DT_RELA = 7          # RELA relocation 테이블 주소
    DT_RELASZ = 8        # RELA relocation 테이블 크기
    DT_RELAENT = 9       # RELA 엔트리 크기
    DT_STRSZ = 10        # 문자열 테이블 크기
    DT_SYMENT = 11       # 심볼 테이블 엔트리 크기
    DT_INIT = 12         # 초기화 함수 주소 (_init)
    DT_FINI = 13         # 종료 함수 주소 (_fini)
    DT_SONAME = 14       # 공유 객체 이름 (strtab 오프셋)
    DT_RPATH = 15        # 라이브러리 검색 경로 (deprecated, DT_RUNPATH 사용)
    DT_SYMBOLIC = 16     # 심볼릭 링크 해석 시작 플래그
    DT_REL = 17          # REL relocation 테이블 주소
    DT_RELSZ = 18        # REL relocation 테이블 크기
    DT_RELENT = 19       # REL 엔트리 크기
    DT_PLTREL = 20       # PLT에서 사용하는 relocation 타입 (DT_REL or DT_RELA)
    DT_DEBUG = 21        # 디버깅용 (동적 링커가 사용)
    DT_TEXTREL = 22      # 텍스트 섹션에 relocation이 있음 (보안상 나쁨)
    DT_JMPREL = 23       # PLT relocation 테이블 주소
    DT_BIND_NOW = 24     # 즉시 바인딩 (lazy binding 비활성화)
    
    # === GNU 확장 (25-34) ===
    DT_INIT_ARRAY = 25   # 초기화 함수 포인터 배열 주소
    DT_FINI_ARRAY = 26   # 종료 함수 포인터 배열 주소
    DT_INIT_ARRAYSZ = 27 # DT_INIT_ARRAY 크기
    DT_FINI_ARRAYSZ = 28 # DT_FINI_ARRAY 크기
    DT_RUNPATH = 29      # 라이브러리 검색 경로 (DT_RPATH보다 우선)
    DT_FLAGS = 30        # 플래그 (DF_ORIGIN, DF_SYMBOLIC 등)
    
    # DT_ENCODING = 32   # 이 값 이상은 인코딩에 따라 해석
    DT_PREINIT_ARRAY = 32    # 사전 초기화 함수 배열
    DT_PREINIT_ARRAYSZ = 33  # DT_PREINIT_ARRAY 크기
    DT_SYMTAB_SHNDX = 34     # 심볼 테이블 섹션 인덱스
    
    # === GNU 해시 (0x6ffffef5) ===
    DT_GNU_HASH = 0x6ffffef5  # GNU 해시 테이블 (DT_HASH보다 빠름)
    
    # === GNU 버전 관리 (0x6ffffef8 - 0x6fffffff) ===
    DT_VERSYM = 0x6ffffff0     # 버전 심볼 테이블
    DT_RELACOUNT = 0x6ffffff9  # RELA relocation 개수 (R_*_RELATIVE만)
    DT_RELCOUNT = 0x6ffffffa   # REL relocation 개수
    DT_FLAGS_1 = 0x6ffffffb    # 추가 플래그 (DF_1_NOW, DF_1_PIE 등)
    DT_VERDEF = 0x6ffffffc     # 버전 정의 테이블
    DT_VERDEFNUM = 0x6ffffffd  # 버전 정의 개수
    DT_VERNEED = 0x6ffffffe    # 필요한 버전 테이블
    DT_VERNEEDNUM = 0x6fffffff # 필요한 버전 개수
    
    # === Android 확장 (0x6000000d - 0x6000002f) ===
    DT_ANDROID_REL = 0x6000000f      # Android packed relocations (REL)
    DT_ANDROID_RELSZ = 0x60000010    # Android REL 크기
    DT_ANDROID_RELA = 0x60000011     # Android packed relocations (RELA)
    DT_ANDROID_RELASZ = 0x60000012   # Android RELA 크기
    DT_ANDROID_RELR = 0x6fffe000     # Android RELR (상대 relocation)
    DT_ANDROID_RELRSZ = 0x6fffe001   # RELR 크기
    DT_ANDROID_RELRENT = 0x6fffe003  # RELR 엔트리 크기
    DT_ANDROID_RELRCOUNT = 0x6fffe005 # RELR 개수
    
    # === 프로세서별 (0x70000000 - 0x7fffffff) ===
    DT_LOPROC = 0x70000000   # 프로세서 특화 태그 시작
    DT_HIPROC = 0x7fffffff   # 프로세서 특화 태그 끝
    
    # ARM 특화
    DT_ARM_SYMTABSZ = 0x70000001  # ARM 심볼 테이블 크기
    DT_ARM_PREEMPTMAP = 0x70000002 # ARM preemption map
    
    # MIPS 특화
    DT_MIPS_RLD_VERSION = 0x70000001
    DT_MIPS_TIME_STAMP = 0x70000002
    DT_MIPS_SYMTABNO = 0x70000011    # MIPS 심볼 개수
    DT_MIPS_GOTSYM = 0x70000013      # GOT에 있는 첫 심볼
    DT_MIPS_LOCAL_GOTNO = 0x7000000a # 로컬 GOT 엔트리 개수

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

@dataclass
class DynamicEntry:
    """Dynamic 엔트리 정보"""
    d_tag: int
    d_val: int

    def __str__(self):
        try:
            tag_name = DynamicTag(self.d_tag).name
        except ValueError:
            tag_name = f"0x{self.d_tag:08x}"
        return f"DynamicEntry(d_tag={tag_name}, d_val=0x{self.d_val:016x})"


class ELFParser:
    ELF_MAGIC = b'\x7fELF'

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.elf_header = None
        self.program_headers = []
        self.section_headers = []
        self.dynamic_entries: list[DynamicEntry] = []
        with open(self.file_path, 'rb') as f:
            self.data = f.read()

    def parse(self):
        # ELF 파일 파싱 로직 구현
        if self.parse_elf_header():
            print("\n--- ELF Header parsed successfully! ---")
            print(self.elf_header)
        if self.parse_program_header():
            print("\n--- ProgramHeader parsed successfully! ---")
            print(self.program_headers)
        if self.parse_dynamic_section():
            print("\n--- Dynamic Section parsed successfully! ---")
            for entry in self.dynamic_entries:
                print(entry)

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
    
    def parse_dynamic_section(self):

        for ph in self.program_headers:
            if ph.p_type == ProgramHeaderType.PT_DYNAMIC:
                dynanic_offset = ph.p_offset
                break

        if dynanic_offset is None:
            return False
        
        # Dynamic 섹션 파싱 로직 구현
        # 예시: Dynamic 엔트리 파싱
        self.dynamic_entries = []
        dynamic_ent_size = 16  # Dynamic 엔트리는 16바이트
        while True:
            entry_data = self.data[dynanic_offset:dynanic_offset+dynamic_ent_size]
            # if len(entry_data) < dynamic_ent_size:
            #     break
            d_tag, d_val = unpack('<QQ', entry_data)  # Little Endian 기준
            if d_tag == 0:  # DT_NULL
                break
            self.dynamic_entries.append(DynamicEntry(d_tag=d_tag, d_val=d_val))
            dynanic_offset += dynamic_ent_size
        return True