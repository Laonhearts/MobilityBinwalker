import os
import binwalk.core.common
import binwalk.core.plugin

class ArcadyanDeobfuscator(binwalk.core.plugin.Plugin):

    '''
    Arcadyan 펌웨어의 알려진 난독화 방법을 해독하는 플러그인 클래스입니다.
    '''
    
    # 이 플러그인이 적용될 모듈을 지정합니다.
    MODULES = ['Signature']

    # 난독화된 데이터의 크기와 관련된 상수들
    OBFUSCATION_MAGIC_SIZE = 4
    MAX_IMAGE_SIZE = 0x1B0000  # 최대 이미지 크기
    BLOCK_SIZE = 32  # 블록의 크기
    BLOCK1_OFFSET = 4  # 첫 번째 블록의 오프셋
    BLOCK2_OFFSET = 0x68  # 두 번째 블록의 오프셋
    MIN_FILE_SIZE = (OBFUSCATION_MAGIC_SIZE + BLOCK2_OFFSET + BLOCK_SIZE)  # 최소 파일 크기

    # 블록 시작 및 종료 오프셋을 정의합니다.
    BLOCK1_START = BLOCK1_OFFSET
    BLOCK1_END = BLOCK1_START + BLOCK_SIZE

    BLOCK2_START = BLOCK2_OFFSET
    BLOCK2_END = BLOCK2_OFFSET + BLOCK_SIZE

    # 각 섹션의 시작 및 종료 오프셋을 정의합니다.
    P1_START = 0
    P1_END = BLOCK1_OFFSET

    P2_START = BLOCK1_END
    P2_END = BLOCK2_START

    P3_START = BLOCK2_END

    def init(self):
        # 플러그인이 초기화될 때 호출됩니다.
        # 추출기가 활성화된 경우, 난독화된 Arcadyan 펌웨어를 처리하는 규칙을 추가합니다.
        if self.module.extractor.enabled:
            self.module.extractor.add_rule(
                regex="^obfuscated arcadyan firmware",
                extension="obfuscated",
                cmd=self.extractor
            )

    def extractor(self, fname):
        # 난독화된 펌웨어를 해독하는 함수입니다.
        deobfuscated = None
        fname = os.path.abspath(fname)

        # 입력 파일을 읽습니다.
        infile = binwalk.core.common.BlockFile(fname, "rb")
        obfuscated = infile.read(self.MIN_FILE_SIZE)
        infile.close()

        # 파일 크기가 허용된 최대 크기를 초과하는지 확인합니다.
        if os.path.getsize(fname) > self.MAX_IMAGE_SIZE:
            raise Exception("Arcadyan 난독화된 펌웨어에 대한 입력 파일이 너무 큽니다.")

        # 최소 파일 크기보다 큰 경우 해독을 시도합니다.
        if len(obfuscated) >= self.MIN_FILE_SIZE:
            # 블록 1과 블록 2를 교체합니다.
            p1 = obfuscated[self.P1_START:self.P1_END]
            b1 = obfuscated[self.BLOCK1_START:self.BLOCK1_END]
            p2 = obfuscated[self.P2_START:self.P2_END]
            b2 = obfuscated[self.BLOCK2_START:self.BLOCK2_END]
            p3 = obfuscated[self.P3_START:]
            deobfuscated = p1 + b2 + p2 + b1 + p3

            # 블록 1의 각 바이트에 대해 니블 스왑(nibble-swap)을 수행합니다.
            nswap = ''
            for i in range(self.BLOCK1_START, self.BLOCK1_END):
                nswap += chr(((ord(deobfuscated[i]) & 0x0F) << 4) + ((ord(deobfuscated[i]) & 0xF0) >> 4))
            deobfuscated = deobfuscated[self.P1_START:self.P1_END] + nswap + deobfuscated[self.BLOCK1_END:]

            # 블록 1의 각 바이트 쌍에 대해 바이트 스왑(byte-swap)을 수행합니다.
            bswap = ''
            i = self.BLOCK1_START
            while i < self.BLOCK1_END:
                bswap += deobfuscated[i + 1] + deobfuscated[i]
                i += 2
            deobfuscated = deobfuscated[self.P1_START:self.P1_END] + bswap + deobfuscated[self.BLOCK1_END:]

        # 해독된 데이터가 있으면 새 파일에 저장합니다.
        if deobfuscated:
            out = binwalk.core.common.BlockFile((os.path.splitext(fname)[0] + '.deobfuscated'), "wb")
            out.write(deobfuscated)
            out.close()
            return True
        else:
            return False
