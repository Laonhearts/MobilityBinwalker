import sys
import string
import binwalk.core.common as common
from binwalk.core.compat import *
from binwalk.core.module import Module, Option, Kwarg

class HexDiff(Module):

    # 색상 설정 (ANSI escape codes)
    COLORS = {
        'red': '31',   # 차이가 있는 부분을 빨간색으로 표시
        'green': '32', # 동일한 부분을 초록색으로 표시
        'blue': '34',  # 일부 차이가 있는 부분을 파란색으로 표시
    }

    SEPERATORS = ['\\', '/']  # 각 파일 간의 구분 기호
    DEFAULT_BLOCK_SIZE = 16  # 기본 블록 크기 (한 줄에 표시할 바이트 수)

    SKIPPED_LINE = "*"  # 건너뛴 라인 표시
    SAME_DIFFERENCE = "~"  # 동일한 차이 라인 표시
    CUSTOM_DISPLAY_FORMAT = "0x%.8X    %s"  # 결과 출력 형식

    TITLE = "Binary Diffing"  # 모듈의 제목

    # 명령줄 인터페이스 옵션 설정
    CLI = [
        Option(short='W',
               long='hexdump',
               kwargs={'enabled': True},
               description='파일 또는 파일들에 대해 hexdump / diff 수행'),
        Option(short='G',
               long='green',
               kwargs={'show_green': True},
               description='모든 파일 간 동일한 바이트를 포함하는 라인만 표시'),
        Option(short='i',
               long='red',
               kwargs={'show_red': True},
               description='모든 파일 간 다른 바이트를 포함하는 라인만 표시'),
        Option(short='U',
               long='blue',
               kwargs={'show_blue': True},
               description='일부 파일 간 다른 바이트를 포함하는 라인만 표시'),
        Option(short='u',
               long='similar',
               kwargs={'show_same': True},
               description='모든 파일 간 동일한 라인만 표시'),
        Option(short='w',
               long='terse',
               kwargs={'terse': True},
               description='모든 파일을 diff하지만, 첫 번째 파일의 hexdump만 표시'),
    ]

    # 클래스 초기화 시 사용할 기본 값들
    KWARGS = [
        Kwarg(name='show_red', default=False),
        Kwarg(name='show_blue', default=False),
        Kwarg(name='show_green', default=False),
        Kwarg(name='terse', default=False),
        Kwarg(name='show_same', default=False),
        Kwarg(name='enabled', default=False),
    ]

    RESULT_FORMAT = "%s\n"  # 결과 출력 형식
    RESULT = ['display']  # 결과에 표시할 속성

    def _no_colorize(self, c, color="red", bold=True):
        # 색상 처리를 하지 않는 경우
        return c

    def _colorize(self, c, color="red", bold=True):
        # 주어진 텍스트에 색상과 볼드 속성을 적용
        attr = []

        attr.append(self.COLORS[color])
        if bold:
            attr.append('1')

        return "\x1b[%sm%s\x1b[0m" % (';'.join(attr), c)

    def _color_filter(self, data):
        # 지정된 색상 필터에 따라 라인을 필터링
        red = '\x1b[' + self.COLORS['red'] + ';'
        green = '\x1b[' + self.COLORS['green'] + ';'
        blue = '\x1b[' + self.COLORS['blue'] + ';'

        if self.show_blue and blue in data:
            return True
        elif self.show_green and green in data:
            return True
        elif self.show_red and red in data:
            return True

        return False

    def hexascii(self, target_data, byte, offset):
        # 주어진 바이트에 대해 색상을 설정하고 ASCII로 변환
        color = "green"

        for (fp_i, data_i) in iterator(target_data):
            diff_count = 0

            for (fp_j, data_j) in iterator(target_data):
                if fp_i == fp_j:
                    continue

                try:
                    if data_i[offset] != data_j[offset]:
                        diff_count += 1
                except IndexError as e:
                    diff_count += 1

            if diff_count == len(target_data) - 1:
                color = "red"
            elif diff_count > 0:
                color = "blue"
                break

        hexbyte = self.colorize("%.2X" % ord(byte), color)

        if byte not in string.printable or byte in string.whitespace:
            byte = "."

        asciibyte = self.colorize(byte, color)

        return (hexbyte, asciibyte)

    def diff_files(self, target_files):
        # 여러 파일을 비교하여 차이를 출력하는 함수
        last_raw_line = None
        last_line = None
        loop_count = 0
        sep_count = 0

        # 최대 비교 크기(가장 큰 파일 크기)를 설정
        self.status.total = 0
        for i in range(0, len(target_files)):
            if target_files[i].size > self.status.total:
                self.status.total = target_files[i].size
                self.status.fp = target_files[i]

        while True:
            line = ""
            current_raw_line = ""
            done_files = 0
            block_data = {}
            seperator = self.SEPERATORS[sep_count % 2]

            for fp in target_files:
                block_data[fp] = fp.read(self.block)
                if not block_data[fp]:
                    done_files += 1

            # 모든 파일에서 더 이상 데이터가 없으면 종료
            if done_files == len(target_files):
                break

            for fp in target_files:
                hexline = ""
                asciiline = ""

                for i in range(0, self.block):
                    if i >= len(block_data[fp]):
                        hexbyte = "XX"
                        asciibyte = "."
                    else:
                        (hexbyte, asciibyte) = self.hexascii(block_data, block_data[fp][i], i)

                    hexline += "%s " % hexbyte
                    asciiline += "%s" % asciibyte

                line += "%s |%s|" % (hexline, asciiline)

                if self.terse:
                    break

                if fp != target_files[-1]:
                    current_raw_line += line
                    line += " %s " % seperator

            offset = fp.offset + (self.block * loop_count)

            if current_raw_line == last_raw_line and self.show_same == True:
                display = line = self.SAME_DIFFERENCE
            elif not self._color_filter(line):
                display = line = self.SKIPPED_LINE
            else:
                display = self.CUSTOM_DISPLAY_FORMAT % (offset, line)
                sep_count += 1

            if (line not in [self.SKIPPED_LINE, self.SAME_DIFFERENCE] or
                    (last_line != line and
                        (last_line not in [self.SKIPPED_LINE, self.SAME_DIFFERENCE] or
                         line not in [self.SKIPPED_LINE, self.SAME_DIFFERENCE]))):
                self.result(offset=offset, description=line, display=display)

            last_line = line
            last_raw_line = current_raw_line
            loop_count += 1
            self.status.completed += self.block

    def init(self):
        # 모든 옵션이 False인 경우, 모든 데이터를 표시하도록 설정
        if not any([self.show_red, self.show_green, self.show_blue]):
            self.show_red = self.show_green = self.show_blue = True

        # 터미널 형식 설정을 비활성화 (색상화된 출력과 함께 제대로 작동하지 않음)
        self.config.display.fit_to_screen = False

        # 블록 크기 설정 (hexdump 라인 크기)
        self.block = self.config.block
        if not self.block:
            self.block = self.DEFAULT_BLOCK_SIZE

        # 비교할 파일 목록 작성
        self.hex_target_files = []
        while True:
            f = self.next_file(close_previous=False)
            if not f:
                break
            else:
                self.hex_target_files.append(f)

        # 헤더 형식 문자열 작성
        header_width = (self.block * 4) + 2
        if self.terse:
            file_count = 1
        else:
            file_count = len(self.hex_target_files)
        self.HEADER_FORMAT = "OFFSET      " + \
            (("%%-%ds   " % header_width) * file_count) + "\n"

        # 헤더 인수 목록 작성
        self.HEADER = [fp.name for fp in self.hex_target_files]
        if self.terse and len(self.HEADER) > 1:
            self.HEADER = self.HEADER[0]

        # 색상화 지원이 있는지 확인하여 설정
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty() and not common.MSWindows():
            import curses
            curses.setupterm()
            self.colorize = self._colorize
        else:
            self.colorize = self._no_colorize

    def run(self):
        # 모듈 실행 시 호출되는 메인 함수
        if self.hex_target_files:
            self.header()
            self.diff_files(self.hex_target_files)
            self.footer()
