import os
import binwalk.core.plugin


class LZMAExtractPlugin(binwalk.core.plugin.Plugin):

    '''
    LZMA 압축 해제 플러그인.
    '''
    MODULES = ['Signature']  # 이 플러그인이 적용될 모듈을 지정합니다.

    def init(self):
        try:
            # Python 2.0의 lzma 패키지의 decompress()는 여러 개의 압축 스트림을 처리하지 못하고,
            # 첫 번째 스트림만 추출합니다. backports.lzma 패키지를 사용하면 일관된 동작을 유지할 수 있습니다.
            try:
                import lzma
            except ImportError:
                from backports import lzma

            self.decompressor = lzma.decompress

            # 현재 로드된 모듈에서 추출기가 활성화된 경우,
            # self.extractor를 lzma 압축 해제 규칙으로 등록합니다.
            if self.module.extractor.enabled:
                self.module.extractor.add_rule(txtrule=None,
                                               regex="^lzma compressed data",
                                               extension="7z",
                                               cmd=self.extractor,
                                               prepend=True)  # lzma 압축 데이터에 대해 규칙 추가
                self.module.extractor.add_rule(txtrule=None,
                                               regex="^xz compressed data",
                                               extension="xz",
                                               cmd=self.extractor,
                                               prepend=True)  # xz 압축 데이터에 대해 규칙 추가
        except ImportError as e:
            if self.module.extractor.enabled:
                binwalk.core.common.warning("Python LZMA 모듈을 찾을 수 없습니다. Binwalk이 올바른 LZMA 식별 및 추출 결과를 제공하려면 이 모듈을 설치하는 것이 *강력히* 권장됩니다.")


    def extractor(self, fname):
        fname = os.path.abspath(fname)  # 파일의 절대 경로를 얻습니다.
        outfile = os.path.splitext(fname)[0]  # 확장자를 제거하여 출력 파일 이름을 생성합니다.

        try:
            fpin = open(fname, "rb")
            compressed = fpin.read()  # 압축된 데이터를 읽어옵니다.
            fpin.close()

            decompressed = self.decompressor(compressed)  # 압축 해제 작업을 수행합니다.

            fpout = open(outfile, "wb")
            fpout.write(decompressed)  # 압축 해제된 데이터를 출력 파일에 씁니다.
            fpout.close()
        except KeyboardInterrupt as e:
            raise e  # 사용자가 인터럽트를 걸었을 경우 예외를 다시 발생시킵니다.
        except Exception as e:
            return False  # 다른 예외가 발생했을 경우 False를 반환합니다.

        return True  # 압축 해제 작업이 성공적으로 완료되었을 경우 True를 반환합니다.
