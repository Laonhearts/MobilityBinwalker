# 데이터 추출 규칙에 일치하는 데이터를 추출합니다.
# 사용자가 추출 기능을 활성화한 경우, core.module 코드에 의해 자동으로 호출됩니다.
# 다른 모듈에서 이 모듈을 직접 참조할 필요는 없습니다.

import os
import re
import pwd
import stat
import shlex
import tempfile
import subprocess
import binwalk.core.common
from binwalk.core.compat import *
from binwalk.core.exceptions import ModuleException
from binwalk.core.module import Module, Option, Kwarg
from binwalk.core.common import file_size, file_md5, unique_file_name, BlockFile

# 각 파일의 추출 세부 정보 저장 클래스
class ExtractDetails(object):
    def __init__(self, **kwargs):
        # 전달된 키워드 인수들을 객체의 속성으로 설정
        for (k, v) in iterator(kwargs):
            setattr(self, k, v)

# 파일의 추출 정보 저장 클래스
class ExtractInfo(object):
    def __init__(self):
        self.carved = {}      # 추출된 데이터 블록 정보 저장
        self.extracted = {}   # 추출된 파일 정보 저장
        self.directory = None # 추출이 이루어진 디렉터리 경로 저장

# 추출 작업을 수행하는 메인 클래스
class Extractor(Module):

    '''
    Extractor 클래스는 대상 파일에서 데이터를 추출하고, 필요시 외부 애플리케이션을 실행하는 역할을 합니다.
    '''
    # 추출 규칙은 콜론(:)으로 구분됩니다.
    # <대소문자 구분 없이 일치하는 문자열>:<파일 확장자>[:<실행할 명령>]
    RULE_DELIM = ':'

    # extract.conf 파일에서 주석은 #으로 시작합니다.
    COMMENT_DELIM = '#'

    # 명령어에서 추출된 파일 이름을 나타내는 플레이스홀더
    FILE_NAME_PLACEHOLDER = '%e'

    # 고유한 출력 파일/디렉터리 이름을 생성하기 위한 구분자
    UNIQUE_PATH_DELIMITER = '%%'

    # 클래스의 메타정보
    TITLE = 'Extraction'
    ORDER = 9
    PRIMARY = False

    # CLI 옵션 설정
    CLI = [
        Option(short='e',
               long='extract',
               kwargs={'load_default_rules': True, 'enabled': True},
               description='알려진 파일 형식을 자동으로 추출'),
        Option(short='D',
               long='dd',
               type=list,
               dtype='type[:ext[:cmd]]',
               kwargs={'manual_rules': [], 'enabled': True},
               description='<type> 서명을 추출하고, 파일 확장자를 <ext>로 지정하며, <cmd> 명령을 실행'),
        Option(short='M',
               long='matryoshka',
               kwargs={'matryoshka': 8},
               description='추출된 파일을 재귀적으로 스캔'),
        Option(short='d',
               long='depth',
               type=int,
               kwargs={'matryoshka': 0},
               description='마트료시카 재귀 깊이 제한 (기본값: 8 단계)'),
        Option(short='C',
               long='directory',
               type=str,
               kwargs={'base_directory': 0},
               description='파일/폴더를 사용자 정의 디렉토리로 추출 (기본값: 현재 작업 디렉토리)'),
        Option(short='j',
               long='size',
               type=int,
               kwargs={'max_size': 0},
               description='각 추출 파일의 크기 제한'),
        Option(short='n',
               long='count',
               type=int,
               kwargs={'max_count': 0},
               description='추출 파일의 수 제한'),
        Option(short='0',
               long='run-as',
               type=str,
               kwargs={'runas_user': 0},
               description="외부 추출 유틸리티를 지정된 사용자 권한으로 실행"),
        Option(short='1',
               long='preserve-symlinks',
               kwargs={'do_not_sanitize_symlinks': True},
               description="추출된 심볼릭 링크를 추출 디렉터리 외부로 포인트하지 않도록 정리하지 않음 (위험할 수 있음)"),
        Option(short='r',
               long='rm',
               kwargs={'remove_after_execute': True},
               description='추출 후 추출된 파일을 삭제'),
        Option(short='z',
               long='carve',
               kwargs={'run_extractors': False},
               description="파일에서 데이터를 추출하지만 추출 유틸리티를 실행하지 않음"),
        Option(short='V',
               long='subdirs',
               kwargs={'extract_into_subdirs': True},
               description="오프셋으로 명명된 하위 디렉터리에 추출"),
    ]

    # 키워드 인수 설정
    KWARGS = [
        Kwarg(name='max_size', default=None),  # 최대 파일 크기 제한
        Kwarg(name='recursive_max_size', default=None),  # 재귀 최대 크기 제한
        Kwarg(name='max_count', default=None),  # 최대 추출 파일 수
        Kwarg(name='base_directory', default=None),  # 기본 디렉터리 설정
        Kwarg(name='do_not_sanitize_symlinks', default=False),  # 심볼릭 링크 정리 비활성화 여부
        Kwarg(name='remove_after_execute', default=False),  # 실행 후 파일 제거 여부
        Kwarg(name='load_default_rules', default=False),  # 기본 규칙 로드 여부
        Kwarg(name='run_extractors', default=True),  # 추출 유틸리티 실행 여부
        Kwarg(name='extract_into_subdirs', default=False),  # 하위 디렉터리로 추출 여부
        Kwarg(name='manual_rules', default=[]),  # 수동 규칙 목록
        Kwarg(name='matryoshka', default=0),  # 재귀 깊이
        Kwarg(name='enabled', default=False),  # 모듈 활성화 여부
        Kwarg(name='runas_user', default=None),  # 실행 사용자
    ]

    def load(self):
        self.runas_uid = None  # 실행할 사용자 ID
        self.runas_gid = None  # 실행할 사용자 그룹 ID

        if self.enabled is True:
            if self.runas_user is None:
                # 현재 실행 중인 사용자 정보 가져오기
                user_info = pwd.getpwuid(os.getuid())

                # 루트 권한으로 실행하지 않도록 제한
                if user_info.pw_uid == 0:
                    raise ModuleException("Binwalk 추출은 보안에 취약할 수 있는 여러 서드파티 유틸리티를 사용합니다. 현재 사용자로 추출 유틸리티를 실행하려면 '--run-as=%s' 옵션을 사용하십시오. (Binwalk 자체는 루트로 실행되어야 합니다.)" % user_info.pw_name)

                # 외부 애플리케이션을 현재 사용자로 실행
                self.runas_uid = user_info.pw_uid
                self.runas_gid = user_info.pw_gid
            else:
                # 지정된 사용자로 외부 애플리케이션 실행
                user_info = pwd.getpwnam(self.runas_user)
                self.runas_uid = user_info.pw_uid
                self.runas_gid = user_info.pw_gid

                # 다른 사용자로 전환할 권한이 있는지 확인
                if self.runas_uid != os.getuid() and os.getuid() != 0:
                    raise ModuleException("%s로 서드파티 애플리케이션을 실행하려면, Binwalk을 루트 권한으로 실행해야 합니다." % self.runas_user)

        # 로드된 추출 규칙 목록 저장
        self.extract_rules = []
        # 파일별 출력 디렉터리 경로 (기본값은 현재 작업 디렉터리)
        if self.base_directory:
            self.directory = os.path.realpath(self.base_directory)
            if not os.path.exists(self.directory):
                os.makedirs(self.directory)
        else:
            self.directory = os.getcwd()
        # 입력 파일 경로와 출력 추출 경로의 키-값 쌍
        self.output = {}
        # 추출된 파일 수
        self.extraction_count = 0
        # 추출 출력 디렉터리 이름 재정의
        self.output_directory_override = None

        if self.load_default_rules:
            self.load_defaults()

        for manual_rule in self.manual_rules:
            self.add_rule(manual_rule)

        if self.matryoshka:
            self.config.verbose = True

    def add_pending(self, f):
        # 심볼릭 링크를 무시하고 재귀가 요청되지 않은 경우 새 파일을 추가하지 않음
        if os.path.islink(f) or not self.matryoshka:
            return

        # 파일 모드를 가져와서 블록/문자 장치인지 확인
        try:
            file_mode = os.stat(f).st_mode
        except OSError as e:
            return

        # 파일이 일반 파일인 경우에만 대기 목록에 추가
        if stat.S_ISREG(file_mode):
            # 파일을 열 수 있는지 확인
            try:
                fp = binwalk.core.common.BlockFile(f)
                fp.close()
                self.pending.append(f)
            except IOError as e:
                binwalk.core.common.warning("파일 '%s'을(를) 무시합니다: %s" % (f, str(e)))
        else:
            binwalk.core.common.warning("파일 '%s'을(를) 무시합니다: 일반 파일이 아닙니다" % f)

    def reset(self):
        # 대기 중인 파일 목록 초기화; self.matryoshka == True 인 경우에만 채워짐
        self.pending = []
        # 각 스캔된 파일에 대해 생성된 추출 디렉터리의 사전
        self.extraction_directories = {}
        # 각 디렉터리에 대한 마지막 디렉터리 목록의 사전; 새로 생성된/추출된 파일을 식별하는 데 사용됨
        self.last_directory_listing = {}

    def callback(self, r):
        # 파일 속성이 binwalk.core.common.BlockFile의 호환 가능한 인스턴스로 설정되었는지 확인
        try:
            r.file.size
        except KeyboardInterrupt as e:
            pass
        except Exception as e:
            return

        if not r.size:
            size = r.file.size - r.offset
        else:
            size = r.size

        # 유효한 결과만 추출하며, 사용자에게 표시된 결과만 추출
        if r.valid and r.extract and r.display and (not self.max_count or self.extraction_count < self.max_count):
            # 이 파일에 대한 출력이 아직 생성되지 않은 경우 생성
            if not binwalk.core.common.has_key(self.output, r.file.path):
                self.output[r.file.path] = ExtractInfo()

            # 추출 시도
            binwalk.core.common.debug("Extractor callback for %s @%d [%s]" % (r.file.name,
                                                                              r.offset,
                                                                              r.description))
            (extraction_directory, dd_file, scan_extracted_files, extraction_utility) = self.extract(r.offset,
                                                                                                     r.description,
                                                                                                     r.file.path,
                                                                                                     size,
                                                                                                     r.name)

            # 추출이 성공하면 self.extract는 출력 디렉터리와 추출된 파일 이름을 반환
            if extraction_directory and dd_file:
                # 추출된 파일 수 추적
                self.extraction_count += 1

                # 추출된 파일의 전체 경로를 가져와서 이 파일의 출력 정보에 저장
                dd_file_path = os.path.join(extraction_directory, dd_file)
                self.output[r.file.path].carved[r.offset] = dd_file_path
                self.output[r.file.path].extracted[r.offset] = ExtractDetails(files=[], command=extraction_utility)

                # 출력 디렉터리의 디렉터리 목록 생성
                directory_listing = set(os.listdir(extraction_directory))

                # 이 디렉터리가 새로 생성된 경우, self.last_directory_listing에 기록되지 않았을 수 있음
                if not has_key(self.last_directory_listing, extraction_directory):
                    self.last_directory_listing[extraction_directory] = set()

                # 마지막 디렉터리 목록에 없었던 새로 생성된 파일을 루프
                for f in directory_listing.difference(self.last_directory_listing[extraction_directory]):
                    # 전체 파일 경로를 빌드하고 추출기 결과에 추가
                    file_path = os.path.join(extraction_directory, f)
                    real_file_path = os.path.realpath(file_path)
                    self.result(description=file_path, display=False)

                    # 추출 유틸리티에 의해 생성된 파일 목록도 유지
                    if real_file_path != dd_file_path:
                        binwalk.core.common.debug("파일 목록에 %s (%s) (%s) 추가" % (file_path, f, real_file_path))
                        self.output[r.file.path].extracted[r.offset].files.append(file_path)

                    # 재귀가 지정된 경우, 그리고 이 파일이 방금 추출한 파일과 다를 경우
                    if file_path != dd_file_path:
                        # 심볼릭 링크가 추출 디렉터리 외부를 가리키지 않도록 보안상 정리
                        self.symlink_sanitizer(file_path, extraction_directory)

                        # 이 파일이 디렉터리이고, 이 추출기에서 디렉터리를 처리해야 하는 경우
                        if os.path.isdir(file_path):
                            for root, dirs, files in os.walk(file_path):
                                # 심볼릭 링크가 추출 디렉터리 외부를 가리키지 않도록 보안상 정리
                                self.symlink_sanitizer([os.path.join(root, x) for x in dirs+files], extraction_directory)

                                for f in files:
                                    full_path = os.path.join(root, f)

                                    # 이 파일의 재귀 레벨이 원하는 재귀 레벨보다 작거나 같은 경우
                                    if len(real_file_path.split(self.directory)[1].split(os.path.sep)) <= self.matryoshka:
                                        if scan_extracted_files and self.directory in real_file_path:
                                                self.add_pending(full_path)

                        # 만약 이것이 파일이라면 대기 파일 목록에 추가
                        elif scan_extracted_files and self.directory in real_file_path:
                            self.add_pending(file_path)

                # 다음에 이 동일한 출력 디렉터리에 파일을 추출할 때를 위해 마지막 디렉터리 목록 업데이트
                self.last_directory_listing[extraction_directory] = directory_listing

    def append_rule(self, r):
        # 추출 규칙 목록에 규칙을 추가
        self.extract_rules.append(r.copy())

    def prepend_rule(self, r):
        # 추출 규칙 목록의 앞에 규칙을 추가
        self.extract_rules = [r] + self.extract_rules

    def add_rule(self, txtrule=None, regex=None, extension=None, cmd=None, codes=[0, None], recurse=True, prepend=False):
        # 추출 규칙 생성 및 추가
        rules = self.create_rule(txtrule, regex, extension, cmd, codes, recurse)
        for r in rules:
            if prepend:
                self.prepend_rule(r)
            else:
                self.append_rule(r)

    def create_rule(self, txtrule=None, regex=None, extension=None, cmd=None, codes=[0, None], recurse=True):
        '''
        추출 규칙 목록에 규칙 세트를 추가합니다.

        @txtrule   - <정규 표현식>:<파일 확장자>[:<실행할 명령>] 형식의 규칙 문자열 또는 규칙 문자열 목록.
        @regex     - 규칙 문자열이 지정되지 않은 경우 사용할 정규 표현식 문자열.
        @extension - 규칙 문자열이 지정되지 않은 경우 사용할 파일 확장자.
        @cmd       - 규칙 문자열이 지정되지 않은 경우 실행할 명령.
                     대안으로는 하나의 인수(추출할 파일 경로)를 받는 호출 가능한 객체를 지정할 수 있습니다.
        @codes     - 추출기 성공을 나타내는 유효한 반환 코드 목록.
        @recurse   - False로 설정하면 마트료시카 옵션이 활성화되었을 때 추출된 디렉터리 내부를 재귀적으로 처리하지 않습니다.

        규칙 목록을 반환합니다.
        '''
        rules = []
        created_rules = []
        match = False
        r = {
            'extension': '',
            'cmd': '',
            'regex': None,
            'codes': codes,
            'recurse': recurse,
        }

        # 명시적으로 지정된 규칙 처리
        if not txtrule and regex and extension:
            r['extension'] = extension
            r['regex'] = re.compile(regex)
            if cmd:
                r['cmd'] = cmd

            return [r]

        # 규칙 문자열 또는 규칙 문자열 목록 처리
        if not isinstance(txtrule, type([])):
            rules = [txtrule]
        else:
            rules = txtrule

        for rule in rules:
            r['cmd'] = ''
            r['extension'] = ''

            try:
                values = self._parse_rule(rule)
                match = values[0]
                r['regex'] = re.compile(values[0])
                r['extension'] = values[1]
                r['cmd'] = values[2]
                r['codes'] = values[3]
                r['recurse'] = values[4]
            except KeyboardInterrupt as e:
                raise e
            except Exception:
                pass

            # 매치 문자열이 검색되었는지 확인
            if match:
                created_rules.append(r)

        return created_rules

    def remove_rules(self, description):
        '''
        지정된 설명과 일치하는 모든 규칙을 제거합니다.

        @description - 일치시킬 설명.

        제거된 규칙 수를 반환합니다.
        '''
        rm = []
        description = description.lower()

        for i in range(0, len(self.extract_rules)):
            if self.extract_rules[i]['regex'].search(description):
                rm.append(i)

        for i in rm:
            self.extract_rules.pop(i)

        return len(rm)

    def edit_rules(self, description, key, value):
        '''
        지정된 설명과 일치하는 모든 규칙을 수정합니다.

        @description - 일치시킬 설명.
        @key         - 각 일치 규칙에 대해 변경할 키.
        @value       - 각 일치 규칙에 대한 새로운 키 값.

        수정된 규칙 수를 반환합니다.
        '''
        count = 0
        description = description.lower()

        for i in range(0, len(self.extract_rules)):
            if self.extract_rules[i]['regex'].search(description):
                if has_key(self.extract_rules[i], key):
                    self.extract_rules[i][key] = value
                    count += 1

        return count

    def clear_rules(self):
        '''
        모든 추출 규칙을 삭제합니다.

        반환 값 없음.
        '''
        self.extract_rules = []

    def get_rules(self, description=None):
        '''
        지정된 설명과 일치하는 추출 규칙 목록을 반환합니다.

        @description - 일치시킬 설명.

        지정된 설명과 일치하는 추출 규칙 목록을 반환합니다.
        설명이 제공되지 않은 경우, 모든 규칙 목록을 반환합니다.
        '''
        if description:
            rules = []
            description = description.lower()
            for i in range(0, len(self.extract_rules)):
                if self.extract_rules[i]['regex'].search(description):
                    rules.append(self.extract_rules[i])
        else:
            rules = self.extract_rules

        return rules

    def load_from_file(self, fname):
        '''
        지정된 파일에서 추출 규칙을 로드합니다.

        @fname - 추출 규칙 파일의 경로.

        반환 값 없음.
        '''
        try:
            # extract 파일에서 각 줄을 처리하고, 주석을 무시함
            with open(fname, 'r') as f:
                for rule in f.readlines():
                    self.add_rule(rule.split(self.COMMENT_DELIM, 1)[0])
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            raise Exception("Extractor.load_from_file 파일 '%s' 로드 실패: %s" % (fname, str(e)))

    def load_defaults(self):
        '''
        사용자 및 시스템 extract.conf 파일에서 기본 추출 규칙을 로드합니다.

        반환 값 없음.
        '''
        # 사용자 extract 파일을 먼저 로드하여 그 규칙이 우선 적용되도록 함
        extract_files = [
            self.config.settings.user.extract,
            self.config.settings.system.extract,
        ]

        for extract_file in extract_files:
            if extract_file:
                try:
                    self.load_from_file(extract_file)
                except KeyboardInterrupt as e:
                    raise e
                except Exception as e:
                    if binwalk.core.common.DEBUG:
                        raise Exception("Extractor.load_defaults 파일 '%s' 로드 실패: %s" % (extract_file, str(e)))

    def get_output_directory_override(self):
        '''
        현재 출력 디렉터리 이름 재정의 값을 반환합니다.
        '''
        return self.output_directory_override

    def override_output_directory_basename(self, dirname):
        '''
        기본 추출 디렉터리 이름을 재정의합니다.

        @dirname - 사용할 디렉터리 기본 이름.

        현재 출력 디렉터리 이름 재정의 값을 반환합니다.
        '''
        self.output_directory_override = dirname
        return self.output_directory_override

    def build_output_directory(self, path):
        '''
        추출 파일의 출력 디렉터리를 설정합니다.

        @path - 데이터가 추출될 파일의 경로.

        반환 값 없음.
        '''
        # 이 대상 파일에 대한 출력 디렉터리가 아직 생성되지 않은 경우, 지금 생성
        if not has_key(self.extraction_directories, path):
            basedir = os.path.dirname(path)
            basename = os.path.basename(path)

            if basedir != self.directory:
                # 재귀 추출 동안 추출된 파일은 현재 작업 디렉터리의 하위 디렉터리에 있습니다.
                # 이 하위 디렉터리는 대상 파일의 기본 디렉터리를 현재 작업 디렉터리에서 분할하여 식별할 수 있습니다.
                #
                # 그러나 첫 번째로 스캔되는 파일은 반드시 현재 작업 디렉터리에 있지 않을 수 있으므로 IndexError가 발생할 수 있습니다.
                # 이 경우에 대비하여, 처음 스캔되는 파일의 내용은 ${CWD}/_basename.extracted에 추출되어야 하므로, IndexError가 발생할 때는 subdir 변수를 빈 문자열로 설정합니다.
                try:
                    subdir = basedir.split(self.directory)[1][1:]
                except IndexError as e:
                    subdir = ""
            else:
                subdir = ""

            if self.output_directory_override:
                output_directory = os.path.join(self.directory, subdir, self.output_directory_override)
            else:
                outdir = os.path.join(self.directory, subdir, '_' + basename)
                output_directory = unique_file_name(outdir, extension='extracted')

            if not os.path.exists(output_directory):
                os.mkdir(output_directory)

            self.extraction_directories[path] = output_directory
            self.output[path].directory = os.path.realpath(output_directory) + os.path.sep
        # 그렇지 않으면 이미 생성된 디렉터리 사용
        else:
            output_directory = self.extraction_directories[path]

        # 실행할 사용자가 이 디렉터리에 접근할 수 있는지 확인
        os.chown(output_directory, self.runas_uid, self.runas_gid)

        return output_directory

    def cleanup_extracted_files(self, tf=None):
        '''
        파일이 추출된 후 취할 조치를 설정합니다.

        @tf - True로 설정하면 파일에 대해 명령을 실행한 후 추출된 파일이 정리됩니다.
              False로 설정하면 파일에 대해 명령을 실행한 후 추출된 파일이 정리되지 않습니다.
              None 또는 지정되지 않은 경우 현재 설정은 변경되지 않습니다.

        현재 정리 상태(True/False)를 반환합니다.
        '''
        if tf is not None:
            self.remove_after_execute = tf

        return self.remove_after_execute

    def extract(self, offset, description, file_name, size, name=None):
        '''
        추출 규칙에 일치하는 경우 대상 파일에서 내장 파일을 추출합니다.
        Binwalk.scan()에 의해 자동으로 호출됩니다.

        @offset      - 추출을 시작할 대상 파일 내의 오프셋.
        @description - libmagic에 의해 반환된 내장 파일 설명.
        @file_name   - 대상 파일의 경로.
        @size        - 추출할 바이트 수.
        @name        - 파일을 저장할 이름.

        추출된 파일의 이름을 반환합니다 (아무 것도 추출되지 않은 경우 빈 문자열).
        '''
        fname = ''
        rule = None
        recurse = False
        command_line = ''
        original_dir = os.getcwd()
        rules = self.match(description)
        file_path = os.path.realpath(file_name)

        # 이 파일에 대한 추출 규칙이 없는 경우
        if not rules:
            binwalk.core.common.debug("'%s'에 대한 추출 규칙을 찾을 수 없습니다." % description)
            return (None, None, False, str(None))
        else:
            binwalk.core.common.debug("일치하는 추출 규칙 %d개 발견" % len(rules))

        # 추출된 파일이 저장될 출력 디렉터리 이름 생성
        output_directory = self.build_output_directory(file_name)

        # 크기가 지정되지 않은 경우 파일 끝까지 추출
        if not size:
            size = file_size(file_path) - offset

        if os.path.isfile(file_path):
            binwalk.core.common.debug("디렉터리를 다음으로 변경: %s" % output_directory)
            os.chdir(output_directory)

            # 오프셋으로 명명된 하위 디렉터리에 추출
            if self.extract_into_subdirs:
                # hex()에 의해 추가된 끝에 있는 L을 제거
                offset_dir = "0x%X" % offset
                os.mkdir(offset_dir)
                os.chdir(offset_dir)

            # 각 추출 규칙을 반복하여 하나가 성공할 때까지 시도
            for i in range(0, len(rules)):
                rule = rules[i]

                binwalk.core.common.debug("추출 규칙 #%d (%s) 처리 중" % (i, str(rule['cmd'])))

                # 추출된 디렉터리로 재귀하지 않도록 지시된 경우 확인
                if rule['recurse'] in [True, False]:
                    recurse = rule['recurse']
                else:
                    recurse = True

                binwalk.core.common.debug("%s[%d:]에서 %s로 추출 중" % (file_path, offset, name))

                # 아직 데이터를 디스크에 복사하지 않은 경우 복사
                fname = self._dd(file_path, offset, size, rule['extension'], output_file_name=name)

                # 이 규칙에 대해 명령이 지정된 경우 실행 시도
                # 실행에 실패하면 다음 규칙이 시도됨
                if rule['cmd']:

                    # 원본 파일의 해시 기록; --rm이 지정되고 추출 유틸리티가 새 파일을 생성하는 대신 원본 파일을 수정하는 경우
                    if self.remove_after_execute:
                        fname_md5 = file_md5(fname)

                    binwalk.core.common.debug("추출 명령 실행 중 %s" % (str(rule['cmd'])))

                    # 추출된 파일에 대해 지정된 명령 실행
                    if self.run_extractors:
                        (extract_ok, command_line) = self.execute(rule['cmd'], fname, rule['codes'])
                    else:
                        extract_ok = True
                        command_line = ''

                    binwalk.core.common.debug("추출 명령 실행: %s" % command_line)
                    binwalk.core.common.debug("추출 성공: %s" % extract_ok)

                    # remove_after_execute가 지정된 경우에만 파일 정리
                    # 파일이 성공적으로 추출된 경우에만 정리; 그렇지 않으면 남아있음
                    if self.remove_after_execute and (extract_ok == True or i == (len(rules) - 1)):

                        # 추출된 원본 파일이 추출기에 의해 수정되지 않은 경우 삭제
                        try:
                            if file_md5(fname) == fname_md5:
                                os.unlink(fname)
                        except KeyboardInterrupt as e:
                            raise e
                        except Exception as e:
                            pass

                    # 명령이 성공적으로 실행된 경우, 더 이상의 규칙 시도 중지
                    if extract_ok == True:
                        break
                    # 그렇지 않으면, 목록의 마지막 규칙이 아닌 경우 추출된 파일을 삭제
                    # 마지막 규칙인 경우 사용자가 파일을 검사할 수 있도록 디스크에 남겨둠
                    elif i != (len(rules) - 1):
                        try:
                            os.unlink(fname)
                        except KeyboardInterrupt as e:
                            raise e
                        except Exception as e:
                            pass

                # 실행할 명령이 없었던 경우, 첫 번째 규칙을 사용
                else:
                    break

            binwalk.core.common.debug("디렉터리 다시 변경: %s" % original_dir)
            os.chdir(original_dir)

        return (output_directory, fname, recurse, command_line)

    def _entry_offset(self, index, entries, description):
        '''
        지정된 설명과 일치하는 첫 번째 항목의 오프셋을 가져옵니다.

        @index       - 검색을 시작할 항목 목록의 인덱스.
        @entries     - 결과 항목의 사전.
        @description - 대소문자 구분 없이 설명.

        일치하는 설명이 발견된 경우 오프셋을 반환.
        일치하는 설명이 발견되지 않은 경우 -1을 반환.
        '''
        description = description.lower()

        for (offset, infos) in entries[index:]:
            for info in infos:
                if info['description'].lower().startswith(description):
                    return offset
        return -1

    def match(self, description):
        '''
        제공된 설명 문자열이 추출 규칙과 일치하는지 확인합니다.
        내부적으로 self.extract()에 의해 호출됩니다.

        @description - 확인할 설명 문자열.

        일치하는 규칙이 발견된 경우 관련 규칙 사전을 반환.
        일치하는 규칙이 발견되지 않은 경우 None을 반환.
        '''
        rules = []
        ordered_rules = []
        description = description.lower()

        for rule in self.extract_rules:
            if rule['regex'].search(description):
                rules.append(rule)

        # 플러그인 규칙은 외부 추출 명령보다 우선 적용되어야 합니다.
        for rule in rules:
            if callable(rule['cmd']):
                ordered_rules.append(rule)
        for rule in rules:
            if not callable(rule['cmd']):
                ordered_rules.append(rule)

        binwalk.core.common.debug("'%s'에 대한 %d/%d개의 일치하는 규칙 발견" % (description, len(ordered_rules), len(self.extract_rules)))
        return ordered_rules

    def _parse_rule(self, rule):
        '''
        추출 규칙을 구문 분석합니다.

        @rule - 규칙 문자열.

        ['<대소문자 구분 없이 일치하는 문자열>', '<파일 확장자>', '<실행할 명령>', '<쉼표로 구분된 반환 코드>', <추출된 디렉터리로 재귀할지 여부: True|False>] 배열을 반환합니다.
        '''
        values = rule.strip().split(self.RULE_DELIM, 4)

        if len(values) >= 4:
            codes = values[3].split(',')
            for i in range(0, len(codes)):
                try:
                    codes[i] = int(codes[i], 0)
                except ValueError as e:
                    binwalk.core.common.warning("추출기 '%s'의 지정된 반환 코드 '%s'가 유효한 숫자가 아닙니다!" % (values[0], codes[i]))
            values[3] = codes

        if len(values) >= 5:
            values[4] = (values[4].lower() == 'true')

        return values

    def _dd(self, file_name, offset, size, extension, output_file_name=None):
        '''
        대상 파일 내부의 내장 파일을 추출합니다.

        @file_name        - 대상 파일의 경로.
        @offset           - 내장 파일이 시작되는 대상 파일 내의 오프셋.
        @size             - 추출할 바이트 수.
        @extension        - 디스크에 추출된 파일에 할당할 파일 확장자.
        @output_file_name - 요청된 출력 파일 이름.

        추출된 파일 이름을 반환합니다.
        '''
        total_size = 0
        # 기본 추출 파일 이름은 <표시된 16진수 오프셋>.<확장자>
        default_bname = "%X" % (offset + self.config.base)

        # 출력 파일 이름이 문자열인지 확인
        if output_file_name is not None:
            output_file_name = str(output_file_name)

        if self.max_size and size > self.max_size:
            size = self.max_size

        if not output_file_name or output_file_name is None:
            bname = default_bname
        else:
            # 출력 파일 이름에서 잘못된/위험한 문자(파일 경로 등) 제거
            bname = os.path.basename(output_file_name)

        fname = unique_file_name(bname, extension)

        try:
            # 바이트 스왑이 활성화된 경우, 스왑 크기 정렬된 오프셋에서 읽기 시작한 다음 읽은 데이터를 적절히 인덱싱해야 합니다.
            if self.config.swap_size:
                adjust = offset % self.config.swap_size
            else:
                adjust = 0

            offset -= adjust

            # 대상 파일을 열고 오프셋으로 이동
            fdin = self.config.open_file(file_name)
            fdin.seek(offset)

            # 출력 파일 열기
            try:
                fdout = BlockFile(fname, 'w')
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                # 요청된 이름이 실패할 경우 기본 이름으로 다시 시도
                fname = unique_file_name(default_bname, extension)
                fdout = BlockFile(fname, 'w')

            while total_size < size:
                (data, dlen) = fdin.read_block()
                if dlen < 1:
                    break
                else:
                    total_size += (dlen - adjust)
                    if total_size > size:
                        dlen -= (total_size - size)
                    fdout.write(str2bytes(data[adjust:dlen]))
                    adjust = 0

            # 정리
            fdout.close()
            fdin.close()

            # 실행할 사용자가 이 파일에 접근할 수 있는지 확인
            os.chown(fname, self.runas_uid, self.runas_gid)
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            raise Exception("Extractor.dd '%s'에서 '%s'로 데이터 추출 실패: %s" %
                            (file_name, fname, str(e)))

        binwalk.core.common.debug("'%s'에서 '%s'로 데이터 블록 0x%X - 0x%X 추출" %
                                  (file_name, fname, offset, offset + size))
        return fname

    def execute(self, cmd, fname, codes=[0, None]):
        '''
        지정된 파일에 대해 명령을 실행합니다.

        @cmd   - 실행할 명령.
        @fname - 명령을 실행할 파일.
        @codes - cmd 성공을 나타내는 반환 코드 목록.

        성공 시 True, 실패 시 False, 외부 추출 유틸리티를 찾을 수 없는 경우 None을 반환합니다.
        '''
        rval = 0
        retval = True
        command_list = []

        binwalk.core.common.debug("추출기 '%s' 실행 중" % str(cmd))

        try:
            if callable(cmd):
                command_list.append(get_class_name_from_method(cmd))

                try:
                    retval = cmd(fname)
                except KeyboardInterrupt as e:
                    raise e
                except Exception as e:
                    retval = False
                    binwalk.core.common.warning("내부 추출기 '%s' 실패 예외: '%s'" % (str(cmd), str(e)))
            elif cmd:
                # 현재 명령에 UNIQUE_PATH_DELIMITER로 둘러싸인 모든 경로에 대해 고유 파일 경로 생성
                while self.UNIQUE_PATH_DELIMITER in cmd:
                    need_unique_path = cmd.split(self.UNIQUE_PATH_DELIMITER)[1].split(self.UNIQUE_PATH_DELIMITER)[0]
                    unique_path = binwalk.core.common.unique_file_name(need_unique_path)
                    cmd = cmd.replace(self.UNIQUE_PATH_DELIMITER + need_unique_path + self.UNIQUE_PATH_DELIMITER, unique_path)

                # 명령 실행
                for command in cmd.split("&&"):

                    # 명령에서 FILE_NAME_PLACEHOLDER의 모든 인스턴스를 fname으로 대체
                    command = command.strip().replace(self.FILE_NAME_PLACEHOLDER, fname)

                    # 외부 추출기 실행
                    rval = self.shell_call(command)

                    # 반환 값을 확인하여 추출이 성공했는지 여부 확인
                    if rval in codes:
                        retval = True
                    else:
                        retval = False

                    binwalk.core.common.debug('외부 추출기 명령 "%s" 완료, 반환 코드 %d (성공: %s)' % (cmd, rval, str(retval)))
                    command_list.append(command)

        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            binwalk.core.common.warning("Extractor.execute 외부 추출기 '%s' 실행 실패: %s, '%s'이(가) 올바르게 설치되지 않았을 수 있습니다." % (str(cmd), str(e), str(cmd)))
            retval = None

        return (retval, '&&'.join(command_list))

    def shell_call(self, command):
        # 디버그 모드가 아닌 경우 출력 경로를 /dev/null로 리디렉션
        if not binwalk.core.common.DEBUG:
            tmp = subprocess.DEVNULL
        else:
            tmp = None

        # 실행할 사용자가 현재 사용자가 아닌 경우, 해당 사용자 계정으로 전환해야 함
        if self.runas_uid != os.getuid():
            binwalk.core.common.debug("권한을 %s (%d:%d)로 전환 중" % (self.runas_user, self.runas_uid, self.runas_gid))
            
            # 자식 프로세스 포크
            child_pid = os.fork()
            if child_pid is 0:
                # 실행할 사용자 권한으로 전환, 설정된 경우
                if self.runas_uid is not None and self.runas_gid is not None:
                    os.setgid(self.runas_uid)
                    os.setuid(self.runas_gid)
        else:
            # child_pid가 None이면 os.fork()가 발생하지 않음
            child_pid = None
            
        # 자식 프로세스이거나 os.fork()가 발생하지 않은 경우 명령 실행
        if child_pid in [0, None]:
            binwalk.core.common.debug("subprocess.call(%s, stdout=%s, stderr=%s)" % (command, str(tmp), str(tmp)))
            rval = subprocess.call(shlex.split(command), stdout=tmp, stderr=tmp)

        # 진정한 자식 프로세스는 subprocess 종료 값으로 종료해야 함
        if child_pid is 0:
            sys.exit(rval)
        # os.fork()가 발생하지 않은 경우, subprocess 종료 값을 반환
        elif child_pid is None:
            return rval
        # os.fork()가 발생했으며 부모 프로세스인 경우, 자식 프로세스의 종료 값을 대기하고 반환
        else:
            return os.wait()[1]

    def symlink_sanitizer(self, file_list, extraction_directory):
        # 사용자가 이 기능을 비활성화할 수 있음
        if self.do_not_sanitize_symlinks is True:
            return 

        # 단일 파일 경로 또는 정리할 파일 경로 목록을 전달할 수 있음
        if type(file_list) is not list:
            file_list = [file_list]

        # 지정된 추출 디렉터리 외부를 가리키는 심볼릭 링크가 있는 경우 정리
        for file_name in file_list:
            if os.path.islink(file_name):
                linktarget = os.path.realpath(file_name)
                binwalk.core.common.debug("심볼릭 링크 분석 중: %s -> %s" % (file_name, linktarget))

                if not linktarget.startswith(extraction_directory) and linktarget != os.devnull:
                    binwalk.core.common.warning("심볼릭 링크가 추출 디렉터리 외부를 가리킵니다: %s -> %s; 보안 목적으로 링크 대상이 %s로 변경됩니다." % (file_name, linktarget, os.devnull))
                    os.remove(file_name)
                    os.symlink(os.devnull, file_name)
