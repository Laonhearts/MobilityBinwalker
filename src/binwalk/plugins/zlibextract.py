import os
import zlib
import binwalk.core.compat
import binwalk.core.common
import binwalk.core.plugin


class ZLIBExtractPlugin(binwalk.core.plugin.Plugin):

    '''
    Zlib 추출 플러그인입니다.
    '''
    MODULES = ['Signature']

    def init(self):
        # 이 플러그인이 로드된 모듈에서 추출기가 활성화된 경우,
        # Zlib 압축 데이터를 추출하는 규칙을 등록합니다.
        if self.module.extractor.enabled:
            self.module.extractor.add_rule(txtrule=None,
                                           regex="^zlib compressed data",
                                           extension="zlib",
                                           cmd=self.extractor)

    def extractor(self, fname):
        # 압축 해제된 파일의 출력 파일 이름 설정
        outfile = os.path.splitext(fname)[0]

        try:
            # 입력 파일을 열고 압축된 데이터를 읽어들임
            fpin = binwalk.core.common.BlockFile(fname)
            # 출력 파일을 작성하기 위해 엶
            fpout = binwalk.core.common.BlockFile(outfile, 'w')

            # Zlib로 압축된 데이터를 해제
            plaintext = zlib.decompress(binwalk.core.compat.str2bytes(fpin.read()))
            # 압축 해제된 데이터를 출력 파일에 씀
            fpout.write(plaintext)

            # 파일 포인터를 닫음
            fpin.close()
            fpout.close()
        except KeyboardInterrupt as e:
            # 사용자가 인터럽트를 발생시킨 경우 예외를 다시 발생시킴
            raise e
        except Exception as e:
            # 오류가 발생한 경우 False를 반환
            return False

        # 성공적으로 작업을 완료한 경우 True를 반환
        return True
