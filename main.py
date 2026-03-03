from APKUnpacker import APKUnpacker

if __name__=="__main__":
    unpacker = APKUnpacker("test.apk")
    if unpacker.unpack():
        so_files = unpacker.get_so_files()
        print(so_files)