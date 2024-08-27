import struct
import binascii
import binwalk.core.plugin


class JFFS2ValidPlugin(binwalk.core.plugin.Plugin):

    '''
    JFFS2 서명 결과를 검증하는 플러그인입니다.

    JFFS2 서명 규칙은 명백한 경우를 잘 포착하지만, 노드 사이의 패딩(0xFF 또는 0x00) 때문에
    유효한 일부 JFFS2 노드를 잘못된 것으로 잘못 표시할 수 있습니다.
    '''
    MODULES = ['Signature']  # 이 플러그인이 적용될 모듈을 지정합니다.

    def _check_crc(self, node_header):
        # struct 및 binascii 모듈은 Python3에서 바이트 객체를 원합니다.
        node_header = binwalk.core.compat.str2bytes(node_header)

        # 헤더에 보고된 CRC 값을 가져옵니다.
        if node_header[0:2] == b"\x19\x85":  # 빅 엔디안 형식의 JFFS2 헤더
            header_crc = struct.unpack(">I", node_header[8:12])[0]
        else:  # 리틀 엔디안 형식의 JFFS2 헤더
            header_crc = struct.unpack("<I", node_header[8:12])[0]

        # 실제 CRC를 계산합니다.
        calculated_header_crc = (binascii.crc32(node_header[0:8], -1) ^ -1) & 0xffffffff

        # 계산된 CRC와 헤더에 저장된 CRC가 일치하는지 확인합니다.
        return (header_crc == calculated_header_crc)

    def scan(self, result):
        # JFFS2 파일 시스템 서명이 있는 결과를 처리합니다.
        if result.file and result.description.lower().startswith('jffs2 filesystem'):

            # 의심되는 JFFS2 노드 헤더로 이동하여 데이터를 읽어옵니다.
            fd = self.module.config.open_file(result.file.path, offset=result.offset)
            # JFFS2 헤더는 12바이트 크기이지만, 디스크에서 데이터를 더 많이 읽어오면
            # 반복적인 디스크 액세스를 빠르게 하고 성능 저하를 줄일 수 있습니다 (디스크 캐싱 효과).
            #
            # TODO: 이 플러그인이 시그니처 모듈이 모든 JFFS2 노드를 찾도록 두기보다는
            # 전체 JFFS2 파일 시스템을 검증하도록 해야 할까요?
            node_header = fd.read(1024)
            fd.close()

            # 첫 12바이트 노드 헤더의 CRC가 올바른지 확인하여 유효성 검사 결과를 설정합니다.
            result.valid = self._check_crc(node_header[0:12])
