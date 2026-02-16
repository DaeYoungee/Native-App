import zipfile
import os
import logging
from typing import Dict, List

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ==================== APK 언패커 클래스 ====================

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
        logger.info(f"=== APK 언패킹 시작 ===")
        logger.info(f"APK 경로: {self.apk_path}")
        logger.info(f"출력 디렉토리: {self.output_dir}")

        if not os.path.exists(self.apk_path):
            logger.error(f"APK 파일을 찾을 수 없음: {self.apk_path}")
            return False

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:

                zip_ref.extractall(self.output_dir)
                logger.info(f"APK 언패킹 완료: {self.output_dir}")
                return True

        except zipfile.BadZipFile:
            logger.error("유효하지 않은 APK(ZIP) 파일")
            return False
        except Exception as e:
            logger.error(f"APK 언패킹 실패: {e}")
            return False

    def get_so_files(self) -> List[str]:
        """추출된 .so 파일 경로 목록 반환"""
        return self.so_files

    def get_so_files_by_arch(self) -> Dict[str, List[str]]:
        """아키텍처별 .so 파일 분류"""
        arch_files = {}
        lib = os.path.join(self.output_dir, 'lib')
        for architecture in os.listdir(lib):
            arch_path = os.path.join(lib, architecture)
            if os.path.isdir(arch_path):
                arch_files[architecture] = []
                for file in os.listdir(arch_path):
                    if file.endswith('.so'):
                        arch_files[architecture].append(os.path.join(arch_path, file))
        return arch_files