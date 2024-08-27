import time
import math
import binwalk.core.plugin


class TarPlugin(binwalk.core.plugin.Plugin):

    MODULES = ['Signature']  # 이 플러그인이 적용될 모듈을 지정합니다.

    # Python의 tarfile 모듈에서 차용한 TAR 블록 크기
    TAR_BLOCKSIZE = 512

    def nts(self, s):
        """
        널 종료된 문자열 필드를 파이썬 문자열로 변환합니다.
        """
        # 첫 번째 널 문자가 나올 때까지의 문자열을 사용합니다.
        p = s.find("\0")
        if p == -1:
            return s
        return s[:p]

    def nti(self, s):
        """
        숫자 필드를 파이썬 숫자로 변환합니다.
        """
        # 숫자 필드에 대한 두 가지 가능한 인코딩이 있습니다.
        if s[0] != chr(0x80):  # 일반 8진수 형식
            try:
                n = int(self.nts(s) or "0", 8)  # 8진수로 변환
            except ValueError:
                raise ValueError("유효하지 않은 tar 헤더입니다")
        else:
            n = 0
            for i in range(len(s) - 1):  # 비표준 형식 처리
                n <<= 8
                n += ord(s[i + 1])
        return n

    def scan(self, result):
        if result.description.lower().startswith('posix tar archive'):
            is_tar = True
            file_offset = result.offset
            fd = self.module.config.open_file(result.file.path, offset=result.offset)

            while is_tar:
                # tar 헤더 구조체를 읽습니다.
                buf = fd.read(self.TAR_BLOCKSIZE)

                # 현재 여전히 tarball 내부에 있는지 확인합니다.
                if buf[257:262] == 'ustar':  # TAR 헤더의 매직 넘버 확인
                    # tar에 포함된 파일 크기를 가져와 블록 단위로 변환합니다 (헤더 포함하여 +1 블록)
                    try:
                        size = self.nti(buf[124:136])  # 파일 크기를 추출
                        blocks = math.ceil(size / float(self.TAR_BLOCKSIZE)) + 1  # 필요한 블록 수 계산
                    except ValueError as e:
                        is_tar = False
                        break

                    # tarball 내 다음 파일에 대한 파일 오프셋을 업데이트합니다.
                    file_offset += int(self.TAR_BLOCKSIZE * blocks)

                    if file_offset >= result.file.size:
                        # 파일 끝에 도달한 경우
                        is_tar = False
                    else:
                        fd.seek(file_offset)  # 다음 파일로 이동
                else:
                    is_tar = False  # 더 이상 tarball이 아니라고 판단

            result.jump = file_offset  # 분석을 건너뛸 오프셋을 설정
