import struct
import binascii
import binwalk.core.plugin
import binwalk.core.compat


class UBIValidPlugin(binwalk.core.plugin.Plugin):

    '''
    UBI 소거 카운트 헤더의 서명 결과를 검증하는 데 도움을 줍니다.

    헤더 CRC를 확인하고, 점프 값을 계산합니다.
    '''
    MODULES = ['Signature']  # 이 플러그인이 적용될 모듈을 지정합니다.
    current_file = None  # 현재 처리 중인 파일 경로를 저장합니다.
    last_ec_hdr_offset = None  # 마지막 UBI 소거 카운트 헤더의 오프셋을 저장합니다.
    peb_size = None  # 물리적 지우기 블록(PEB)의 크기를 저장합니다.

    def _check_crc(self, ec_header):
        # 헤더에 기록된 CRC 값을 가져옵니다.
        header_crc = struct.unpack(">I", ec_header[60:64])[0]

        # 실제 CRC를 계산합니다.
        calculated_header_crc = ~binascii.crc32(ec_header[0:60]) & 0xffffffff

        # 두 값이 일치하는지 확인합니다.
        return header_crc == calculated_header_crc

    def _process_result(self, result):
        if self.current_file == result.file.path:
            result.display = False  # 이미 처리된 파일이면 결과를 표시하지 않습니다.
        else:
            # 새로운 파일이 발견된 경우 모든 값을 초기화합니다.
            self.peb_size = None
            self.last_ec_hdr_offset = None
            self.peb_size = None

            # 결과를 표시하고 추출을 트리거합니다.
            result.display = True

        self.current_file = result.file.path  # 현재 파일 경로를 저장합니다.

        if not self.peb_size and self.last_ec_hdr_offset:
            # 마지막 EC 블록 오프셋을 이용해 PEB 크기를 계산합니다.
            self.peb_size = result.offset - self.last_ec_hdr_offset
        else:
            # 파일에서 처음으로 플러그인이 호출된 경우 EC 블록 오프셋을 저장합니다.
            self.last_ec_hdr_offset = result.offset

        if self.peb_size:
            # PEB 크기가 결정되면 해당 크기만큼 점프합니다.
            result.jump = self.peb_size
        else:
            result.jump = 0  # PEB 크기가 결정되지 않은 경우 점프 값을 0으로 설정합니다.

    def scan(self, result):
        if result.file and result.description.lower().startswith('ubi erase count header'):
            # UBI 소거 카운트 헤더로 의심되는 부분을 읽어옵니다.
            fd = self.module.config.open_file(result.file.path, offset=result.offset)

            ec_header = binwalk.core.compat.str2bytes(fd.read(1024))
            fd.close()

            # CRC를 검증하여 유효성을 확인합니다.
            result.valid = self._check_crc(ec_header[0:64])
            if result.valid:
                self._process_result(result)  # 유효한 경우 결과를 처리합니다.
