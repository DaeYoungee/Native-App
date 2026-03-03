import zipfile
import os
import logging
from typing import Dict, List

class APKUnpacker:
    """APK 파일 언패킹 및 .so 파일 추출"""

    def __init__(self, apk_path: str, output_dir: str = None):
        self.apk_path = apk_path
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(apk_path),
            os.path.splitext(os.path.basename(apk_path))[0] + "_unpacked"
        )
        self.so_files: List[str] = []

    def unpack(self) -> bool:
        """APK 언패킹"""
        if not os.path.exists(self.apk_path):
            return False

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:

                zip_ref.extractall(self.output_dir)
                lib = os.path.join(self.output_dir, 'lib')
                for architecture in os.listdir(lib):
                    arch_path = os.path.join(lib, architecture)
                    if os.path.isdir(arch_path):
                        for file in os.listdir(arch_path):
                            if file.endswith('.so'):
                                self.so_files.append(os.path.join(arch_path, file))
                return True

        except Exception as e:
            return False

    def get_so_files(self) -> List[str]:
        """추출된 .so 파일 경로 목록 반환"""
        return self.so_files