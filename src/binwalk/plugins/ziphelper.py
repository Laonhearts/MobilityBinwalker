import binwalk.core.plugin

class ZipHelperPlugin(binwalk.core.plugin.Plugin):

    '''
    Zip 파일에 대한 헬퍼 플러그인입니다.
    첫 번째 Zip 아카이브 항목이 발견되었을 때 Zip 아카이브 추출 규칙이 한 번만 실행되도록 보장합니다.
    Zip 아카이브의 끝이 발견되면 이 플래그를 리셋합니다.
    '''
    MODULES = ['Signature']

    # Zip 아카이브 추출이 활성화되었는지를 추적하는 플래그
    extraction_active = False

    def scan(self, result):
        # 결과가 유효하고 화면에 표시되는 경우
        if result.valid and result.display:
            # Zip 아카이브 데이터가 발견되면
            if result.description.lower().startswith('zip archive data'):
                if self.extraction_active:
                    # 이미 추출이 활성화되어 있으면 추출을 건너뜀
                    result.extract = False
                else:
                    # 첫 번째 Zip 항목이므로 추출을 활성화함
                    self.extraction_active = True
            # Zip 아카이브의 끝이 발견되면 추출 플래그를 리셋함
            elif result.description.lower().startswith('end of zip archive'):
                self.extraction_active = False
