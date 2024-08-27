import binwalk.core.plugin
import binwalk.core.compat
from binwalk.core.common import BlockFile


class LZMAPlugin(binwalk.core.plugin.Plugin):

    '''
    LZMA 서명 결과를 검증하는 플러그인입니다.
    '''
    MODULES = ['Signature']  # 이 플러그인이 적용될 모듈을 지정합니다.

    # 일부 LZMA 파일에는 파일 크기가 포함되지 않으므로, 이를 다시 추가해야 합니다.
    # lzmamod.py 플러그인도 참조하십시오.
    FAKE_LZMA_SIZE = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  # 크기 필드가 없는 경우 사용되는 더미 크기 값

    # 첫 64KB까지 검사합니다.
    MAX_DATA_SIZE = 64 * 1024

    def init(self):
        try:
            try:
                import lzma
            except ImportError:
                from backports import lzma
            self.decompressor = lzma.decompress  # LZMA 압축 해제 함수를 설정합니다.
        except ImportError as e:
            self.decompressor = None  # LZMA 모듈이 없을 경우 None으로 설정합니다.

    def is_valid_lzma(self, data):
        valid = True

        if self.decompressor is not None:
            # 허용되는 예외는 입력 데이터가 잘린 경우뿐입니다.
            try:
                self.decompressor(binwalk.core.compat.str2bytes(data))  # 데이터를 압축 해제 시도
            except IOError as e:
                # Python 2 모듈은 잘린 입력 데이터에 대해 이 오류를 발생시킵니다.
                if str(e) != "unknown BUF error":
                    valid = False
            except Exception as e:
                # Python 3 모듈은 잘린 입력 데이터에 대해 이 오류를 발생시킵니다.
                # 모듈 간의 불일치는 약간 걱정스럽습니다.
                if str(e) != "Compressed data ended before the end-of-stream marker was reached":
                    valid = False

        return valid  # 데이터가 유효한 LZMA 데이터인지 여부를 반환합니다.

    def scan(self, result):
        # 이 결과가 LZMA 서명에 해당하는 경우, 데이터를 압축 해제하여 유효성을 검사합니다.
        if result.valid and result.file and result.description.lower().startswith('lzma compressed data'):

            # LZMA 데이터로 추정되는 부분으로 이동하여 읽습니다.
            fd = self.module.config.open_file(result.file.path, offset=result.offset, length=self.MAX_DATA_SIZE)
            data = fd.read(self.MAX_DATA_SIZE)
            fd.close()

            # 원본 데이터를 검증하고, 실패할 경우 크기 필드가 누락된 것으로 간주하고
            # 더미 크기 필드를 추가한 후 다시 검증합니다.
            if not self.is_valid_lzma(data):
                data = data[:5] + self.FAKE_LZMA_SIZE + data[5:]
                if not self.is_valid_lzma(data):
                    result.valid = False  # 데이터가 유효하지 않다고 표시합니다.
                else:
                    # 압축 해제 크기가 누락된 것으로 설명을 업데이트합니다.
                    result.description = ",".join(result.description.split(',')[:-1] + [" missing uncompressed size"])
