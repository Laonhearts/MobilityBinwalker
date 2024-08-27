import os
import gzip
import binwalk.core.plugin


class GzipExtractPlugin(binwalk.core.plugin.Plugin):

    '''
    Gzip 파일 추출 플러그인입니다.
    '''
    MODULES = ['Signature']
    BLOCK_SIZE = 10 * 1024  # Gzip 파일을 읽어들일 때 사용할 블록 크기 (10KB)입니다.

    def init(self):
        # 플러그인이 로드된 모듈에 대해 추출기가 활성화되어 있고,
        # gzip 서명 결과에 매칭되는 규칙이 이미 존재하는 경우 (예: 기본 규칙이 로드되었거나 gzip 규칙이 수동으로 지정된 경우),
        # 이 플러그인을 gzip 추출 규칙으로 등록합니다.
        if self.module.extractor.enabled and self.module.extractor.match("gzip compressed data"):
            self.module.extractor.add_rule(txtrule=None,
                                           regex="^gzip compressed data",
                                           extension="gz",
                                           cmd=self.extractor)

    def extractor(self, fname):
        # gzip 압축 파일을 추출하는 함수입니다.
        fname = os.path.abspath(fname)  # 입력 파일의 절대 경로를 얻습니다.
        outfile = os.path.splitext(fname)[0]  # 출력 파일명은 입력 파일의 확장자를 제외한 부분으로 설정합니다.

        try:
            fpout = open(outfile, "wb")  # 출력 파일을 쓰기 모드로 엽니다.
            gz = gzip.GzipFile(fname, "rb")  # gzip 파일을 읽기 모드로 엽니다.

            while True:
                data = gz.read(self.BLOCK_SIZE)  # 설정된 블록 크기만큼 데이터를 읽어옵니다.
                if data:
                    fpout.write(data)  # 읽어온 데이터를 출력 파일에 씁니다.
                else:
                    break  # 더 이상 읽을 데이터가 없으면 반복을 종료합니다.

            gz.close()  # gzip 파일을 닫습니다.
            fpout.close()  # 출력 파일을 닫습니다.
        except KeyboardInterrupt as e:
            raise e  # 사용자가 인터럽트를 발생시킨 경우 예외를 발생시킵니다.
        except Exception as e:
            return False  # 예외 발생 시 False를 반환합니다.

        return True  # 성공적으로 추출이 완료되면 True를 반환합니다.
