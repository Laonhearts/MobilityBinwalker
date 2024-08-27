# binwalk 코드 전반에서 사용되는 공통 함수들입니다.

import io
import os
import re
import sys
import ast
import platform
import operator as op
import binwalk.core.idb
from binwalk.core.compat import *

# IDA에 로드된 경우 hashlib을 임포트하지 않음; 작동하지 않기 때문.
if not binwalk.core.idb.LOADED_IN_IDA:
    import hashlib

# __debug__ 값은 기본적으로 True로 설정되어 있지만, Python 인터프리터가 -O 옵션과 함께 실행되면 False로 설정됩니다.
if not __debug__:
    DEBUG = True
else:
    DEBUG = False

def MSWindows():
    # Microsoft Windows OS에서 실행 중인지 확인합니다.
    return (platform.system() == 'Windows')

def debug(msg):
    '''
    Python 인터프리터가 -O 플래그와 함께 호출된 경우에만 stderr로 디버그 메시지를 출력합니다.
    '''
    if DEBUG:
        sys.stderr.write("DEBUG: " + msg + "\n")
        sys.stderr.flush()

def warning(msg):
    '''
    stderr로 경고 메시지를 출력합니다.
    '''
    sys.stderr.write("\nWARNING: " + msg + "\n")

def error(msg):
    '''
    stderr로 오류 메시지를 출력합니다.
    '''
    sys.stderr.write("\nERROR: " + msg + "\n")

def critical(msg):
    '''
    stderr로 치명적인 오류 메시지를 출력합니다.
    '''
    sys.stderr.write("\nCRITICAL: " + msg + "\n")

def get_module_path():
    # 현재 모듈의 경로를 반환합니다.
    root = __file__
    if os.path.islink(root):
        root = os.path.realpath(root)
    return os.path.dirname(os.path.dirname(os.path.abspath(root)))

def get_libs_path():
    # 라이브러리 경로를 반환합니다.
    return os.path.join(get_module_path(), "libs")

def file_md5(file_name):
    '''
    지정된 파일의 MD5 해시를 생성합니다.

    @file_name - 해시할 파일.

    MD5 해시 문자열을 반환합니다.
    '''
    md5 = hashlib.md5()

    with open(file_name, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)

    return md5.hexdigest()

def file_size(filename):
    '''
    주어진 파일의 크기를 얻습니다.

    @filename - 파일의 경로.

    파일 크기를 반환합니다.
    '''
    # open/lseek을 사용하여 정규 파일 및 블록 장치 모두에서 작동하도록 함
    fd = os.open(filename, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    except KeyboardInterrupt as e:
        raise e
    except Exception as e:
        raise Exception(
            "file_size: '%s'의 크기를 얻는 데 실패했습니다: %s" % (filename, str(e)))
    finally:
        os.close(fd)

def strip_quoted_strings(quoted_string):
    '''
    큰따옴표 사이의 데이터를 제거합니다.

    @quoted_string - 제거할 문자열.

    정리된 문자열을 반환합니다.
    '''
    # 이 정규식은 문자열에서 모든 따옴표로 묶인 데이터를 제거합니다.
    # 주의: 첫 번째와 마지막 큰따옴표 사이의 모든 것을 제거합니다.
    # 이는 의도된 동작으로, 대상 파일에서 인쇄된(그리고 인용된) 문자열에 큰따옴표가 포함될 수 있으며,
    # 이 함수는 이를 무시해야 합니다. 그러나 이는 두 따옴표 사이의 모든 데이터도 제거함을 의미합니다.
    return re.sub(r'\"(.*)\"', "", quoted_string)

def get_quoted_strings(quoted_string):
    '''
    큰따옴표 사이의 모든 데이터로 구성된 문자열을 반환합니다.

    @quoted_string - 따옴표로 묶인 데이터를 가져올 문자열.

    성공 시 따옴표로 묶인 문자열을 반환합니다.
    따옴표로 묶인 데이터가 없는 경우 빈 문자열을 반환합니다.
    '''
    try:
        # 이 정규식은 문자열에서 따옴표로 묶인 모든 데이터를 가져옵니다.
        # 주의: 첫 번째와 마지막 큰따옴표 사이의 모든 데이터를 가져옵니다.
        # 이는 의도된 동작으로, 대상 파일에서 인쇄된(그리고 인용된) 문자열에 큰따옴표가 포함될 수 있으며,
        # 이 함수는 이를 무시해야 합니다. 그러나 이는 두 따옴표 사이의 모든 데이터도 포함됨을 의미합니다.
        return re.findall(r'\"(.*)\"', quoted_string)[0]
    except KeyboardInterrupt as e:
        raise e
    except Exception:
        return ''

def unique_file_name(base_name, extension=''):
    '''
    지정된 기본 이름을 기준으로 고유한 파일 이름을 생성합니다.

    @base_name - 고유한 파일 이름으로 사용할 기본 이름.
    @extension - 고유한 파일 이름으로 사용할 파일 확장자.

    고유한 파일 이름 문자열을 반환합니다.
    '''
    idcount = 0

    if extension and not extension.startswith('.'):
        extension = '.%s' % extension

    fname = base_name + extension

    while os.path.exists(fname):
        fname = "%s-%d%s" % (base_name, idcount, extension)
        idcount += 1

    return fname

def strings(filename, minimum=4):
    '''
    Unix의 strings 유틸리티와 유사한 문자열 생성기.

    @filename - 문자열을 검색할 파일.
    @minimum  - 검색할 최소 문자열 길이.

    filename에서 인쇄 가능한 ASCII 문자열을 생성합니다.
    '''
    result = ""

    with BlockFile(filename) as f:
        while True:
            (data, dlen) = f.read_block()
            if dlen < 1:
                break

            for c in data:
                if c in string.printable:
                    result += c
                    continue
                elif len(result) >= minimum:
                    yield result
                    result = ""
                else:
                    result = ""

class GenericContainer(object):

    def __init__(self, **kwargs):
        # 전달된 키워드 인자들을 속성으로 설정
        for (k, v) in iterator(kwargs):
            setattr(self, k, v)

class MathExpression(object):

    '''
    문자열에서 수학적 표현식을 안전하게 평가하는 클래스.
    출처: http://stackoverflow.com/questions/2371436/evaluating-a-mathematical-expression-in-a-string
    '''

    OPERATORS = {
        ast.Add:    op.add,
        ast.UAdd:   op.add,
        ast.USub:   op.sub,
        ast.Sub:    op.sub,
        ast.Mult:   op.mul,
        ast.Div:    op.truediv,
        ast.Pow:    op.pow,
        ast.BitXor: op.xor
    }

    def __init__(self, expression):
        self.expression = expression
        self.value = None

        if expression:
            try:
                self.value = self.evaluate(self.expression)
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                pass

    def evaluate(self, expr):
        # 표현식을 평가하여 값을 계산
        return self._eval(ast.parse(expr).body[0].value)

    def _eval(self, node):
        # 노드의 유형에 따라 수학적 연산 수행
        if isinstance(node, ast.Num):  # 숫자인 경우
            return node.n
        elif isinstance(node, ast.operator):  # 연산자인 경우
            return self.OPERATORS[type(node.op)]
        elif isinstance(node, ast.UnaryOp):
            return self.OPERATORS[type(node.op)](0, self._eval(node.operand))
        elif isinstance(node, ast.BinOp):  # 왼쪽 <연산자> 오른쪽
            return self.OPERATORS[type(node.op)](self._eval(node.left), self._eval(node.right))
        else:
            raise TypeError(node)

class StringFile(object):

    '''
    문자열에 파일처럼 접근할 수 있도록 하는 클래스.
    내부적으로 InternalBlockFile의 조건부 상위 클래스처럼 사용됩니다.
    '''

    def __init__(self, fname, mode='r'):
        self.string = fname # 문자열을 설정
        self.name = "String"
        self.args.size = len(self.string)  # 문자열의 길이를 설정

    def read(self, n=-1):
        # n 바이트만큼 읽거나, n이 -1이면 전체 읽기
        if n == -1:
            data = self.string[self.total_read:]
        else:
            data = self.string[self.total_read:self.total_read + n]
        return data

    def tell(self):
        # 현재 읽은 위치 반환
        return self.total_read

    def write(self, *args, **kwargs):
        # 쓰기 기능은 구현하지 않음
        pass

    def seek(self, *args, **kwargs):
        # 탐색 기능은 구현하지 않음
        pass

    def close(self):
        # 닫기 기능은 구현하지 않음
        pass

def BlockFile(fname, mode='r', subclass=io.FileIO, **kwargs):

    # 함수 내에서 클래스를 정의하면 동적으로 하위 클래스를 생성할 수 있음
    class InternalBlockFile(subclass):

        '''
        이진 파일에 액세스하기 위한 추상화 클래스.

        이 클래스는 io.FilIO의 read 및 write 메서드를 재정의합니다.
        이를 통해 두 가지를 보장합니다:
        
        1. 모든 요청된 데이터가 read 및 write 메서드를 통해 읽히거나 쓰여집니다.
        2. 모든 read는 str 객체를 반환하며, 모든 write는 Python 인터프리터 버전에 관계없이 str 또는 bytes 객체를 받을 수 있습니다.

        단점으로는 다른 io.FileIO 메서드가 Python 3에서 제대로 작동하지 않는다는 점입니다.
        특히 self.read 주위의 래퍼(예: readline, readlines 등)가 문제입니다.

        이 클래스는 또한 binwalk에서 데이터 블록을 읽기 위해 사용되는 read_block 메서드를 제공합니다.
        이 메서드는 추가 데이터(DEFAULT_BLOCK_PEEK_SIZE)를 포함한 데이터 블록을 읽지만, 다음 블록 읽기에서
        이전 데이터 블록의 끝에서 시작하도록 합니다(추가 데이터의 끝이 아님).
        이는 서명이 블록 경계를 가로지를 수 있는 스캔에 필요합니다.

        read가 Python 3에서 bytes 객체 대신 str 객체를 반환하도록 강제하는 것은 의심스러울 수 있지만,
        Python 2/3의 차이를 나머지 코드에서 추상화하고(특히 플러그인 작성 시) 최소한의 코드 변경으로
        Python 3 지원을 추가하기 위한 최선의 방법으로 보였습니다.
        '''

        # DEFAULT_BLOCK_PEEK_SIZE는 서명이 사용할 수 있는 데이터 양을 제한합니다.
        # 대부분의 헤더/서명은 이 값보다 훨씬 작지만, 일부는 헤더 구조의 포인터를 참조할 수 있습니다.
        # 전체 버퍼를 libmagic에 전달하는 것은 자원이 많이 소모되며 스캔 속도를 크게 저하시킬 수 있습니다.
        # 이 값은 스캔 시간을 크게 영향을 미치지 않으면서 libmagic에 전달할 수 있는 합리적인 버퍼 크기를 나타냅니다.
        DEFAULT_BLOCK_PEEK_SIZE = 8 * 1024

        # 한 번에 처리할 최대 바이트 수. 이 값은 디스크 I/O를 제한하기에 충분히 커야 하지만, 처리되는 데이터
        # 블록의 크기를 제한할 만큼 충분히 작아야 합니다.
        DEFAULT_BLOCK_READ_SIZE = 1 * 1024 * 1024

        def __init__(self, fname, mode='r', length=0, offset=0, block=DEFAULT_BLOCK_READ_SIZE, peek=DEFAULT_BLOCK_PEEK_SIZE, swap=0):
            '''
            클래스 생성자.

            @fname  - 열려는 파일의 경로.
            @mode   - 파일을 열 때 사용할 모드(기본값: 'r').
            @length - self.block_read()를 통해 읽을 수 있는 최대 바이트 수.
            @offset - 파일에서 읽기를 시작할 오프셋.
            @block  - 읽을 데이터 블록의 크기(추가 크기 제외).
            @peek   - 각 블록의 끝에 추가할 추가 데이터의 크기.
            @swap   - 매 n 바이트마다 데이터를 반전합니다.

            반환값 없음.
            '''
            self.total_read = 0
            self.block_read_size = self.DEFAULT_BLOCK_READ_SIZE
            self.block_peek_size = self.DEFAULT_BLOCK_PEEK_SIZE

            # 사용자 정의 상위 클래스가 인수에 액세스/수정할 수 있도록 함
            self.args = GenericContainer(fname=fname,
                                         mode=mode,
                                         length=length,
                                         offset=offset,
                                         block=block,
                                         peek=peek,
                                         swap=swap,
                                         size=0)

            # Python 2.6에서는 'rb' 또는 'wb'와 같은 모드를 좋아하지 않음
            mode = self.args.mode.replace('b', '')

            super(self.__class__, self).__init__(fname, mode)

            self.swap_size = self.args.swap

            if self.args.size:
                self.size = self.args.size
            else:
                try:
                    self.size = file_size(self.args.fname)
                except KeyboardInterrupt as e:
                    raise e
                except Exception:
                    self.size = 0

            if self.args.offset < 0:
                self.offset = self.size + self.args.offset
            else:
                self.offset = self.args.offset

            if self.offset < 0:
                self.offset = 0
            elif self.offset > self.size:
                self.offset = self.size

            if self.args.offset < 0:
                self.length = self.args.offset * -1
            elif self.args.length:
                self.length = self.args.length
            else:
                self.length = self.size - self.args.offset

            if self.length < 0:
                self.length = 0
            elif self.length > self.size:
                self.length = self.size

            if self.args.block is not None:
                self.block_read_size = self.args.block
            self.base_block_size = self.block_read_size

            if self.args.peek is not None:
                self.block_peek_size = self.args.peek
            self.base_peek_size = self.block_peek_size

            # Python 2.6에서는 FileIO._name이 정의되지 않음
            try:
                self.name
            except AttributeError:
                self._name = fname

            self.path = os.path.abspath(self.name)
            self.seek(self.offset)

        def _swap_data_block(self, block):
            '''
            지정된 데이터 블록의 매 self.swap_size 바이트를 반전합니다.
            데이터 블록의 크기는 self.swap_size의 배수여야 합니다.

            @block - 반전할 데이터 블록.

            반전된 문자열을 반환합니다.
            '''
            i = 0
            data = ""

            if self.swap_size > 0:
                while i < len(block):
                    data += block[i:i + self.swap_size][::-1]
                    i += self.swap_size
            else:
                data = block

            return data

        def reset(self):
            # 블록 크기와 오프셋을 초기 값으로 재설정
            self.set_block_size(
                block=self.base_block_size, peek=self.base_peek_size)
            self.seek(self.offset)

        def set_block_size(self, block=None, peek=None):
            # 블록 크기와 추가 데이터 크기 설정
            if block is not None:
                self.block_read_size = block
            if peek is not None:
                self.block_peek_size = peek

        def write(self, data):
            '''
            데이터를 열린 파일에 씁니다.

            io.FileIO.write는 모든 데이터가 기록된다는 보장이 없으나,
            이 메서드는 모든 데이터가 기록된다는 보장을 제공합니다.

            기록된 바이트 수를 반환합니다.
            '''
            n = 0
            l = len(data)
            data = str2bytes(data)

            while n < l:
                n += super(self.__class__, self).write(data[n:])

            return n

        def read(self, n=-1, override=False):
            ''''
            최대 n 바이트의 데이터를 읽거나, n이 지정되지 않으면 EOF까지 읽습니다.
            override == True가 아닌 한 self.length 바이트 이상을 읽지 않습니다.

            io.FileIO.read는 모든 요청된 데이터가 읽힌다는 보장이 없으나,
            이 메서드는 모든 데이터가 읽힌다는 보장을 제공합니다.

            읽은 데이터를 포함한 str 객체를 반환합니다.
            '''
            l = 0
            data = b''

            if override == True or (self.total_read < self.length):
                # override가 요청되지 않은 한, self.length 바이트 이상을 파일에서 읽지 않습니다.
                if override == False and (self.total_read + n) > self.length:
                    n = self.length - self.total_read

                while n < 0 or l < n:
                    tmp = super(self.__class__, self).read(n - l)
                    if tmp:
                        data += tmp
                        l += len(tmp)
                    else:
                        break

                self.total_read += len(data)

            return self._swap_data_block(bytes2str(data))

        def peek(self, n=-1):
            '''
            파일의 데이터를 미리 봅니다.
            '''
            pos = self.tell()
            data = self.read(n, override=True)
            self.seek(pos)
            return data

        def seek(self, n, whence=os.SEEK_SET):
            if whence == os.SEEK_SET:
                self.total_read = n - self.offset
            elif whence == os.SEEK_CUR:
                self.total_read += n
            elif whence == os.SEEK_END:
                self.total_read = self.size + n

            super(self.__class__, self).seek(n, whence)

        def read_block(self):
            '''
            대상 파일에서 데이터 블록을 읽습니다.

            (str(파일 블록 데이터), 블록 데이터 길이)의 튜플을 반환합니다.
            '''
            data = self.read(self.block_read_size)
            dlen = len(data)
            data += self.peek(self.block_peek_size)

            return (data, dlen)

    return InternalBlockFile(fname, mode=mode, **kwargs)
