import zlib
import binwalk.core.compat
import binwalk.core.plugin
from binwalk.core.common import BlockFile


class GzipValidPlugin(binwalk.core.plugin.Plugin):

    '''
    gzip 압축 데이터를 검증하는 플러그인입니다. zlibvalid.py와 거의 동일합니다.
    '''
    MODULES = ['Signature']  # 이 플러그인이 적용될 모듈을 지정합니다.

    MAX_DATA_SIZE = 33 * 1024  # 읽을 데이터의 최대 크기 (33KB)입니다.

    def scan(self, result):
        # 결과가 gzip 서명과 일치하는 경우, 데이터를 압축 해제하여 검증합니다.
        if result.file and result.description.lower().startswith('gzip'):
            # 의심되는 gzip 데이터 위치로 이동하고, 데이터를 읽어옵니다.
            fd = self.module.config.open_file(result.file.path, offset=result.offset, length=self.MAX_DATA_SIZE)
            data = fd.read(self.MAX_DATA_SIZE)
            fd.close()

            # 플래그를 가져오고, 압축된 데이터의 시작 오프셋을 초기화합니다.
            flags = int(ord(data[3]))  # gzip 헤더의 4번째 바이트는 플래그입니다.
            offset = 10  # 기본적으로 압축된 데이터는 헤더의 10번째 바이트 이후에 시작됩니다.

            # 주석 또는 원본 파일 이름이 포함된 경우, 해당 문자열의 끝을 찾아 압축 해제 시작 위치를 조정합니다.
            if (flags & 0x0C) or (flags & 0x10):
                while data[offset] != "\x00":  # NULL 문자까지 이동합니다.
                    offset += 1
                offset += 1  # NULL 문자 이후로 이동합니다.

            # 압축된 데이터의 시작 부분에 기본적인 zlib 헤더를 추가합니다.
            data = "\x78\x9C" + data[offset:]

            # 이 데이터가 유효한 deflate 데이터인지 (zlib 헤더가 없는) 확인합니다.
            try:
                zlib.decompress(binwalk.core.compat.str2bytes(data))  # 데이터 압축을 해제합니다.
            except zlib.error as e:
                error = str(e)
                # 입력 데이터가 잘린 경우 -5 오류가 발생합니다.
                # gzip은 zlib과 다른 체크섬을 사용하므로 -3 오류가 발생할 수 있습니다.
                if not error.startswith("Error -5") and not error.startswith("Error -3"):
                    result.valid = False  # 오류가 발생하면 결과를 유효하지 않음으로 표시합니다.
