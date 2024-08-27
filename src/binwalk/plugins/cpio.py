import os
import subprocess
import binwalk.core.common
import binwalk.core.plugin

class CPIOPlugin(binwalk.core.plugin.Plugin):

    '''
    ASCII CPIO 아카이브 항목이 한 번만 추출되도록 보장합니다.
    또한 Unix의 cpio 유틸리티에 대한 내부 CPIO 추출 래퍼를 제공하여
    출력 디렉토리를 직접 지정할 수 없기 때문에 이를 해결합니다.
    '''
    
    # CPIO 아카이브의 기본 출력 디렉토리 이름과 헤더 크기를 정의합니다.
    CPIO_OUT_DIR = "cpio-root"
    CPIO_HEADER_SIZE = 110

    # 이 플러그인이 적용될 모듈을 지정합니다.
    MODULES = ['Signature']

    def init(self):
        # 연속으로 발견된 항목의 수를 초기화합니다.
        self.consecutive_hits = 0

        # 추출기가 활성화된 경우, CPIO 아카이브를 처리하는 규칙을 추가합니다.
        if self.module.extractor.enabled:
            self.module.extractor.add_rule(
                regex="^ascii cpio archive",
                extension="cpio",
                cmd=self.extractor,
                recurse=False  # 대부분의 CPIO 아카이브는 파일 시스템이므로 추출된 내용에 재귀적으로 들어가지 않도록 설정합니다.
            )

    def extractor(self, fname):
        # CPIO 아카이브를 추출하는 함수입니다.
        result = None
        fname = os.path.abspath(fname)
        out_dir_base_name = os.path.join(os.path.dirname(fname), self.CPIO_OUT_DIR)
        out_dir = binwalk.core.common.unique_file_name(out_dir_base_name)

        try:
            # 입력 파일을 읽기 모드로 열고, 에러 출력을 /dev/null로 리디렉션합니다.
            fpin = open(fname, "rb")
            fperr = open(os.devnull, "rb")
            os.mkdir(out_dir)  # 출력 디렉토리를 만듭니다.
        except OSError:
            return False

        try:
            curdir = os.getcwd()  # 현재 작업 디렉토리를 저장합니다.
            os.chdir(out_dir)  # 출력 디렉토리로 이동합니다.
        except OSError:
            return False

        try:
            # CPIO 유틸리티를 사용하여 아카이브를 추출합니다.
            result = subprocess.call(
                ['cpio', '-d', '-i', '--no-absolute-filenames'],
                stdin=fpin,
                stderr=fperr,
                stdout=fperr
            )
        except OSError:
            result = -1

        os.chdir(curdir)  # 원래의 작업 디렉토리로 복귀합니다.
        fpin.close()
        fperr.close()

        # 결과 코드를 확인하여 성공 여부를 반환합니다.
        if result in [0, 2]:
            return True
        else:
            return False

    def pre_scan(self):
        # 매 스캔의 시작에서 설정을 초기화합니다.
        self.found_archive = False
        self.found_archive_in_file = None
        self.consecutive_hits = 0

    def new_file(self, f):
        # 다른 파일로 넘어갈 때 내부 설정이 지속되지 않도록 보장합니다.
        self.pre_scan()

    def _get_file_name(self, description):
        # 설명에서 파일 이름을 추출합니다.
        name = ''
        if 'file name: "' in description:
            name = description.split('file name: "')[1].split('"')[0]
        return name

    def _get_file_name_length(self, description):
        # 설명에서 파일 이름의 길이를 추출합니다.
        length = None
        if 'file name length: "' in description:
            length_string = description.split('file name length: "')[1].split('"')[0]
            try:
                length = int(length_string, 0)
            except ValueError:
                pass
        return length

    def _get_file_size(self, description):
        # 설명에서 파일 크기를 추출합니다.
        size = None
        if 'file size: "' in description:
            size_string = description.split('file size: "')[1].split('"')[0]
            try:
                size = int(size_string, 0)
            except ValueError:
                pass
        return size

    def scan(self, result):
        # 각 스캔 결과를 처리합니다.
        if result.valid:
            # ASCII CPIO 아카이브는 여러 항목으로 구성되며, 'TRAILER!!!'라는 항목으로 끝납니다.
            # 각 항목을 표시하는 것은 아카이브에 포함된 파일을 보여주므로 유용하지만,
            # 첫 번째 항목이 발견될 때만 아카이브를 추출하고자 합니다.
            if result.description.startswith('ASCII cpio archive'):

                # 보고된 파일 이름 길이와 파일 크기를 파싱합니다.
                file_size = self._get_file_size(result.description)
                file_name = self._get_file_name(result.description)
                file_name_length = self._get_file_name_length(result.description)

                # +1은 종료 NULL 바이트를 포함하기 위함입니다.
                if None in [file_size, file_name_length] or file_name_length != len(file_name) + 1:
                    # 보고된 파일 이름의 길이가 실제 파일 이름 길이와 일치하지 않으면,
                    # 이를 잘못된 결과로 처리합니다.
                    result.valid = False
                    return

                # binwalk에 이 CPIO 항목의 나머지 부분을 건너뛰도록 지시합니다.
                result.jump = self.CPIO_HEADER_SIZE + file_size + file_name_length
                self.consecutive_hits += 1

                if not self.found_archive or self.found_archive_in_file != result.file.path:
                    # 이것이 첫 번째 항목인 경우, found_archive를 설정하고 스캔을 계속 진행합니다.
                    self.found_archive_in_file = result.file.path
                    self.found_archive = True
                    result.extract = True
                elif 'TRAILER!!!' in result.description:
                    # 이것이 마지막 항목인 경우, found_archive를 해제합니다.
                    self.found_archive = False
                    result.extract = False
                    self.consecutive_hits = 0
                else:
                    # 첫 번째 항목이 이미 발견되었고, 이것이 마지막 항목이 아니거나
                    # 마지막 항목이 아직 발견되지 않은 경우, 추출하지 않습니다.
                    result.extract = False
            elif self.consecutive_hits < 4:
                # 유효한 비-CPIO 아카이브 결과인 경우, 이러한 값을 초기화합니다.
                # 그렇지 않으면 이전의 잘못된 CPIO 결과로 인해 이후의 유효한 CPIO
                # 결과가 추출되지 않을 수 있습니다.
                self.found_archive = False
                self.found_archive_in_file = None
                self.consecutive_hits = 0
            elif self.consecutive_hits >= 4:
                # CPIO의 끝이 발견될 때까지 다른 것을 무시합니다.
                # TODO: 이 가정을 하기보다는 CPIO 항목의 끝으로 이동하는 것이 더 좋습니다...
                result.valid = False
