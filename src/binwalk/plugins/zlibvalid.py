import zlib
import binwalk.core.compat
import binwalk.core.plugin
from binwalk.core.common import BlockFile


class ZlibValidPlugin(binwalk.core.plugin.Plugin):

    '''
    Zlib 압축 데이터를 검증하는 플러그인입니다.
    '''
    MODULES = ['Signature']

    MAX_DATA_SIZE = 33 * 1024  # 최대 데이터 크기 설정 (33KB)

    def scan(self, result):
        # 이 결과가 zlib 서명과 일치하는 경우 데이터를 압축 해제하여 유효성을 검사합니다.
        if result.file and result.description.lower().startswith('zlib'):

            # 바이트 스와핑이 활성화된 경우, 스왑 크기와 일치하는 오프셋에서 읽기를 시작해야 하므로,
            # 읽어들인 데이터에서 적절한 위치로 인덱싱합니다.
            if self.module.config.swap_size:
                adjust = result.offset % self.module.config.swap_size
            else:
                adjust = 0

            offset = result.offset - adjust

            # 의심되는 zlib 데이터를 찾아서 읽어옵니다.
            fd = self.module.config.open_file(result.file.path)
            fd.seek(offset)
            data = fd.read(self.MAX_DATA_SIZE)[adjust:]
            fd.close()

            # 이 데이터가 유효한 zlib 데이터인지 확인합니다. 유효한 경우는 다음과 같습니다:
            #
            # 1. 오류 없이 압축이 해제될 때
            # 2. 입력 데이터가 잘려서 해제 실패 시
            try:
                zlib.decompress(binwalk.core.compat.str2bytes(data))
            except zlib.error as e:
                # 에러 -5는 데이터 입력이 불완전하거나 잘린 경우입니다.
                if not str(e).startswith("Error -5"):
                    result.valid = False  # 데이터가 유효하지 않다고 표시
