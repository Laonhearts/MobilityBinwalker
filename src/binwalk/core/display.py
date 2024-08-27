# 결과를 화면에 출력하고 로그 파일에 기록하는 작업을 처리하는 코드.
# binwalk에서 결과를 화면에 출력하는 모든 작업은 이 클래스를 사용해야 합니다.

import sys
import csv as pycsv
import datetime
import binwalk.core.common
from binwalk.core.compat import *

class Display(object):

    '''
    출력 및 로그 파일 기록을 처리하는 클래스.
    이 클래스는 모든 모듈에 암시적으로 인스턴스화되며, 대부분의 모듈에서 직접 호출할 필요는 없습니다.
    '''
    SCREEN_WIDTH = 0
    HEADER_WIDTH = 80
    DEFAULT_FORMAT = "%s\n"

    def __init__(self, quiet=False, verbose=False, log=None, csv=False, fit_to_screen=False):
        self.quiet = quiet  # 화면 출력 억제 여부
        self.verbose = verbose  # 자세한 정보 출력 여부
        self.fit_to_screen = fit_to_screen  # 출력 내용을 화면 크기에 맞추는지 여부
        self.fp = None  # 로그 파일 포인터
        self.csv = None  # CSV 로거
        self.num_columns = 0  # 출력 열 수
        self.custom_verbose_format = ""  # 사용자 정의 포맷
        self.custom_verbose_args = []  # 사용자 정의 인자

        self._configure_formatting()

        if log:
            self.fp = open(log, "a")  # 로그 파일 열기
            if csv:
                self.csv = pycsv.writer(self.fp)  # CSV 로거 설정

    def _fix_unicode(self, line):
        '''
        유니코드 문제를 해결하기 위한 임시 방편.
        Python 3에서 LANG=C 환경 변수로 인해 터미널이 ASCII 전용으로 설정되어 있지만,
        유니코드 문자를 출력해야 할 때 UnicodeEncodeError 예외가 발생합니다.
        이 메서드는 주어진 문자열을 ASCII로 변환하며, 변환 오류를 무시합니다.
        '''
        return bytes2str(line.encode('ascii', 'ignore'))

    def _fix_unicode_list(self, columns):
        '''
        self.log에 전달되는 리스트 형식의 포맷 인자에 대해 편리한 래퍼 함수.
        '''
        if type(columns) in [list, tuple]:
            for i in range(0, len(columns)):
                try:
                    columns[i] = self._fix_unicode(columns[i])
                except AttributeError:
                    pass
        return columns

    def format_strings(self, header, result):
        '''
        헤더와 결과 포맷을 설정합니다.
        '''
        self.result_format = result
        self.header_format = header

        if self.num_columns == 0:
            self.num_columns = len(header.split())

    def log(self, fmt, columns):
        '''
        로그 파일에 결과를 기록합니다.
        '''
        if self.fp:
            if self.csv:
                try:
                    self.csv.writerow(columns)
                except UnicodeEncodeError:
                    self.csv.writerow(self._fix_unicode_list(columns))
            else:
                try:
                    self.fp.write(fmt % tuple(columns))
                except UnicodeEncodeError:
                    self.fp.write(fmt % tuple(self._fix_unicode_list(columns)))

            self.fp.flush()

    def add_custom_header(self, fmt, args):
        '''
        사용자 정의 헤더를 추가합니다.
        '''
        self.custom_verbose_format = fmt
        self.custom_verbose_args = args

    def header(self, *args, **kwargs):
        '''
        출력의 헤더를 처리합니다.
        '''
        file_name = None
        self.num_columns = len(args)

        if has_key(kwargs, 'file_name'):
            file_name = kwargs['file_name']

        if self.verbose and file_name:
            md5sum = binwalk.core.common.file_md5(file_name)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if self.csv:
                self.log("", ["FILE", "MD5SUM", "TIMESTAMP"])
                self.log("", [file_name, md5sum, timestamp])

            self._fprint("%s", "\n", csv=False)
            self._fprint("Scan Time:     %s\n", [
                         timestamp], csv=False, filter=False)
            self._fprint("Target File:   %s\n", [
                         file_name], csv=False, filter=False)
            self._fprint(
                "MD5 Checksum:  %s\n", [md5sum], csv=False, filter=False)
            if self.custom_verbose_format and self.custom_verbose_args:
                self._fprint(self.custom_verbose_format,
                             self.custom_verbose_args,
                             csv=False,
                             filter=False)

        self._fprint("%s", "\n", csv=False, filter=False)
        self._fprint(self.header_format, args, filter=False)
        self._fprint("%s", ["-" * self.HEADER_WIDTH + "\n"], csv=False, filter=False)

    def result(self, *args):
        '''
        결과를 출력합니다.
        '''
        # 리스트로 변환하여 항목 할당 가능
        args = list(args)

        # 여러 개의 공백을 단일 공백으로 대체합니다. 이는 설명 문자열에서 실수로 공백이 여러 번 들어가서 자동 포맷팅을 망치지 않도록 하기 위함입니다.
        for i in range(len(args)):
            if isinstance(args[i], str):
                while "    " in args[i]:
                    args[i] = args[i].replace("  ", " ")

        self._fprint(self.result_format, tuple(args))

    def footer(self):
        '''
        출력의 푸터를 처리합니다.
        '''
        self._fprint("%s", "\n", csv=False, filter=False)

    def _fprint(self, fmt, columns, csv=True, stdout=True, filter=True):
        '''
        실제로 출력 작업을 수행하는 내부 함수입니다.
        '''
        line = fmt % tuple(columns)

        if not self.quiet and stdout:
            try:
                try:
                    sys.stdout.write(self._format_line(line.strip()) + "\n")
                except UnicodeEncodeError:
                    line = self._fix_unicode(line)
                    sys.stdout.write(self._format_line(line.strip()) + "\n")
                sys.stdout.flush()
            except IOError as e:
                pass

        if self.fp and not (self.csv and not csv):
            self.log(fmt, columns)

    def _append_to_data_parts(self, data, start, end):
        '''
        데이터를 self.string_parts에 지능적으로 추가합니다.
        self._format에서 사용됩니다.
        '''
        try:
            while data[start] == ' ':
                start += 1

            if start == end:
                end = len(data[start:])

            self.string_parts.append(data[start:end])
        except KeyboardInterrupt as e:
            raise e
        except Exception:
            try:
                self.string_parts.append(data[start:])
            except KeyboardInterrupt as e:
                raise e
            except Exception:
                pass

        return start

    def _format_line(self, line):
        '''
        터미널 창 크기에 맞게 텍스트 라인을 포맷팅합니다.
        '''
        delim = '\n'
        offset = 0
        self.string_parts = []

        # 라인을 열의 배열로 분할합니다. 예: ['0', '0x00000000', 'Some description here']
        line_columns = line.split(None, self.num_columns - 1)
        if line_columns:
            # 텍스트 라인에서 마지막 열(설명)이 시작되는 위치를 찾습니다.
            offset = line.rfind(line_columns[-1])
            # 라인 랩을 맞추기 위한 공백을 포함한 구분자를 설정합니다.
            delim += ' ' * offset

        if line_columns and self.fit_to_screen and len(line) > self.SCREEN_WIDTH:
            # 각 랩된 라인이 가질 수 있는 최대 길이를 계산합니다.
            max_line_wrap_length = self.SCREEN_WIDTH - offset
            formatted_line = line[:offset]

            # 라인을 여러 개의 max_line_wrap_length 조각으로 나누는 루프
            while len(line[offset:]) > max_line_wrap_length:
                split_offset = line[offset:offset + max_line_wrap_length].rfind(' ')
                if split_offset < 1:
                    split_offset = max_line_wrap_length

                self._append_to_data_parts(line, offset, offset + split_offset)
                offset += split_offset

            self._append_to_data_parts(line, offset, offset + len(line[offset:]))

            formatted_line += delim.join(self.string_parts)
        else:
            formatted_line = line

        return formatted_line

    def _configure_formatting(self):
        '''
        출력 포맷팅을 설정하고, 출력 내용을 현재 터미널 너비에 맞춥니다.
        '''
        self.format_strings(self.DEFAULT_FORMAT, self.DEFAULT_FORMAT)

        if self.fit_to_screen:
            try:
                import fcntl
                import struct
                import termios

                # 터미널 창 너비를 가져옵니다.
                hw = struct.unpack('hh', fcntl.ioctl(1, termios.TIOCGWINSZ, '1234'))
                self.SCREEN_WIDTH = self.HEADER_WIDTH = hw[1]
            except KeyboardInterrupt as e:
                raise e
            except Exception:
                pass
