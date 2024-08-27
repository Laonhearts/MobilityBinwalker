# 사용자의 일반적인 입력 옵션(스캔 길이, 시작 오프셋 등)을 처리하는 모듈입니다.

import io
import os
import re
import sys
import argparse
import binwalk.core.idb
import binwalk.core.common
import binwalk.core.display
import binwalk.core.settings
from binwalk.core.compat import *
from binwalk.core.module import Module, Option, Kwarg, show_help


class General(Module):

    TITLE = "General"  # 모듈의 제목
    ORDER = 0  # 모듈 실행 순서

    DEFAULT_DEPENDS = []

    # 명령줄 인터페이스 옵션 설정
    CLI = [
        Option(long='length',
               short='l',
               type=int,
               kwargs={'length': 0},
               description='스캔할 바이트 수'),
        Option(long='offset',
               short='o',
               type=int,
               kwargs={'offset': 0},
               description='파일 오프셋에서 스캔 시작'),
        Option(long='base',
               short='O',
               type=int,
               kwargs={'base': 0},
               description='모든 출력된 오프셋에 기준 주소 추가'),
        Option(long='block',
               short='K',
               type=int,
               kwargs={'block': 0},
               description='파일 블록 크기 설정'),
        Option(long='swap',
               short='g',
               type=int,
               kwargs={'swap_size': 0},
               description='스캔 전에 매 n 바이트마다 순서를 반전'),
        Option(long='log',
               short='f',
               type=argparse.FileType,
               kwargs={'log_file': None},
               description='결과를 파일에 기록'),
        Option(long='csv',
               short='c',
               kwargs={'csv': True},
               description='CSV 형식으로 결과를 파일에 기록'),
        Option(long='term',
               short='t',
               kwargs={'format_to_terminal': True},
               description='출력을 터미널 창에 맞게 형식화'),
        Option(long='quiet',
               short='q',
               kwargs={'quiet': True},
               description='stdout으로의 출력 억제'),
        Option(long='verbose',
               short='v',
               kwargs={'verbose': True},
               description='자세한 출력 활성화'),
        Option(short='h',
               long='help',
               kwargs={'show_help': True},
               description='도움말 출력'),
        Option(short='a',
               long='finclude',
               type=str,
               kwargs={'file_name_include_regex': ""},
               description='이 정규식과 일치하는 파일만 스캔'),
        Option(short='p',
               long='fexclude',
               type=str,
               kwargs={'file_name_exclude_regex': ""},
               description='이 정규식과 일치하는 파일은 스캔하지 않음'),
        Option(short='s',
               long='status',
               type=int,
               kwargs={'status_server_port': 0},
               description='지정된 포트에서 상태 서버 활성화'),
        Option(long=None,
               short=None,
               type=binwalk.core.common.BlockFile,
               kwargs={'files': []}),

        # 숨겨진, API 전용 인자들
        Option(long="string",
               hidden=True,
               kwargs={'subclass': binwalk.core.common.StringFile}),
    ]

    # 클래스 초기화 시 사용할 기본 값들
    KWARGS = [
        Kwarg(name='length', default=0),
        Kwarg(name='offset', default=0),
        Kwarg(name='base', default=0),
        Kwarg(name='block', default=0),
        Kwarg(name='status_server_port', default=0),
        Kwarg(name='swap_size', default=0),
        Kwarg(name='log_file', default=None),
        Kwarg(name='csv', default=False),
        Kwarg(name='format_to_terminal', default=False),
        Kwarg(name='quiet', default=False),
        Kwarg(name='verbose', default=False),
        Kwarg(name='files', default=[]),
        Kwarg(name='show_help', default=False),
        Kwarg(name='keep_going', default=False),
        Kwarg(name='subclass', default=io.FileIO),
        Kwarg(name='file_name_include_regex', default=None),
        Kwarg(name='file_name_exclude_regex', default=None),
    ]

    PRIMARY = False

    def load(self):
        # 모듈 초기화 함수
        self.threads_active = False
        self.target_files = []

        # IDA에서 로드된 경우에 대한 특별한 처리
        if self.subclass == io.FileIO and binwalk.core.idb.LOADED_IN_IDA:
            self.subclass = binwalk.core.idb.IDBFileIO

        # 순서가 중요한 두 가지 메서드 호출
        self._open_target_files()
        self._set_verbosity()

        # 파일 이름 필터 정규식 규칙 빌드
        if self.file_name_include_regex:
            self.file_name_include_regex = re.compile(self.file_name_include_regex)
        if self.file_name_exclude_regex:
            self.file_name_exclude_regex = re.compile(self.file_name_exclude_regex)

        # 설정 및 디스플레이 객체 초기화
        self.settings = binwalk.core.settings.Settings()
        self.display = binwalk.core.display.Display(log=self.log_file,
                                                    csv=self.csv,
                                                    quiet=self.quiet,
                                                    verbose=self.verbose,
                                                    fit_to_screen=self.format_to_terminal)

        # 도움말 표시 및 프로그램 종료
        if self.show_help:
            show_help()
            if not binwalk.core.idb.LOADED_IN_IDA:
                sys.exit(0)

        # 상태 서버를 지정된 포트에서 활성화
        if self.status_server_port > 0:
            self.parent.status_server(self.status_server_port)

    def reset(self):
        # 리셋 시 수행할 작업 (현재는 빈 메서드)
        pass

    def _set_verbosity(self):
        '''
        적절한 자세한 출력 설정.
        self._test_target_files 이후에 호출되어야 하며, self.target_files가 제대로 설정되어야 합니다.
        '''
        # 두 개 이상의 대상 파일이 지정된 경우, 자세한 출력을 활성화
        if len(self.target_files) > 1 and not self.verbose:
            self.verbose = True

    def file_name_filter(self, fp):
        '''
        파일 이름 포함/제외 필터를 기반으로 파일을 스캔할지 여부를 확인.
        Matryoshka 스캔에서 특정 파일만 원하는 경우에 유용합니다.

        @fp - binwalk.common.BlockFile 인스턴스

        스캔해야 하는 파일인 경우 True를 반환하고, 그렇지 않으면 False를 반환합니다.
        '''
        if self.file_name_include_regex and not self.file_name_include_regex.search(fp.name):
            return False
        if self.file_name_exclude_regex and self.file_name_exclude_regex.search(fp.name):
            return False

        return True

    def open_file(self, fname, length=None, offset=None, swap=None, block=None, peek=None):
        '''
        모든 관련 구성 설정으로 지정된 파일을 엽니다.
        '''
        if length is None:
            length = self.length
        if offset is None:
            offset = self.offset
        if swap is None:
            swap = self.swap_size

        return binwalk.core.common.BlockFile(fname,
                                             subclass=self.subclass,
                                             length=length,
                                             offset=offset,
                                             swap=swap,
                                             block=block,
                                             peek=peek)

    def _open_target_files(self):
        '''
        대상 파일을 열 수 있는지 확인.
        열 수 없는 파일은 self.target_files 목록에서 제거됩니다.
        '''
        # target_files에 나열된 대상 파일을 검증
        for tfile in self.files:
            # 디렉토리를 무시
            if not self.subclass == io.FileIO or not os.path.isdir(tfile):
                # 대상 파일을 열 수 있는지 확인
                try:
                    fp = self.open_file(tfile)
                    fp.close()
                    self.target_files.append(tfile)
                except KeyboardInterrupt as e:
                    raise e
                except Exception as e:
                    self.error(description="파일 %s를 열 수 없습니다 (현재 작업 디렉토리: %s) : %s" % (tfile, os.getcwd(), str(e)))
