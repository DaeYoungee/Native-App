from APKUnpacker import APKUnpacker
from elf_parser import ELFParser

if __name__=="__main__":
    unpacker = APKUnpacker("test.apk")
    if unpacker.unpack():
        so_files = unpacker.get_so_files()
    print(so_files[4])
    ELFParser = ELFParser(so_files[4])
    ELFParser.parse()