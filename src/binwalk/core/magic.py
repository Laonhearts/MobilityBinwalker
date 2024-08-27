__all__ = ['Magic']

import re
import struct
import datetime
import binwalk.core.common
import binwalk.core.compat
from binwalk.core.exceptions import ParserException

class SignatureResult(binwalk.core.module.Result):
    '''
    시그니처 결과를 저장하는 클래스입니다.
    '''

    def __init__(self, **kwargs):
        # 시그니처 키워드 태그에 의해 설정되는 값들입니다.
        # 키워드 태그는 binwalk.core.module.Result에 있는
        # 다른 객체 속성들도 설정할 수 있습니다.
        self.jump = 0
        self.many = False
        self.adjust = 0
        self.strlen = 0
        self.string = False
        self.invalid = False
        self.once = False
        self.overlap = False
        self.end = False

        # 내부적으로 코드에 의해 설정되는 값들입니다.
        self.id = 0

        # kwargs가 위의 기본값을 덮어씁니다.
        super(self.__class__, self).__init__(**kwargs)

        self.valid = (not self.invalid)


class SignatureLine(object):
    '''
    매직 시그니처 파일의 시그니처 라인을 파싱하는 클래스입니다.
    '''

    # 출력 문자열이 이 크기로 잘립니다.
    MAX_STRING_SIZE = 128

    def __init__(self, line):
        '''
        클래스 생성자입니다. 시그니처 파일의 라인을 파싱합니다.

        @line - 시그니처 파일의 한 줄.

        반환값은 없습니다.
        '''
        self.tags = {}
        self.text = line
        self.regex = False

        # 공백으로 라인을 나눕니다. 이 작업을 위해, 백슬래시로 이스케이프된 공백('\ ')을
        # 이스케이프된 16진 값('\x20')으로 바꿉니다.
        #
        # [오프셋] [데이터 타입] [비교 값] [포맷 문자열]
        # 0        belong      0x12345678         Foo 파일 타입,
        # >4       string      x                  파일 이름: %s,
        parts = line.replace('\\ ', '\\x20').split(None, 3)

        # 분리된 라인의 유효성을 검사합니다.
        if len(parts) not in [3, 4]:
            raise ParserException("잘못된 시그니처 라인: '%s'" % line)

        # 들여쓰기 수준은 시그니처 라인의 시작 부분에 있는 '>' 문자의 수로 결정됩니다.
        self.level = parts[0].count('>')

        # 들여쓰기 문자를 제거하고 남은 문자를 정수 오프셋으로 변환합니다. 
        # 이 작업은 오프셋이 복합 값인 경우 실패합니다 (예: '(4.l+16)').
        self.offset = parts[0].replace('>', '')
        try:
            self.offset = int(self.offset, 0)
        except ValueError:
            pass

        # self.type은 지정된 데이터 타입 ('belong', 'string', 등)입니다.
        self.type = parts[1]
        self.opvalue = None
        self.operator = None

        # 각 데이터 타입은 비교를 수행하기 전에 데이터를 수정하는 추가 연산을 지정할 수 있습니다
        # (예: 'belong&0xFF'는 비교를 수행하기 전에 데이터를 0xFF와 AND 연산합니다).
        #
        # 다음 연산자를 지원합니다:
        for operator in ['**', '<<', '>>', '&', '|', '*', '+', '-', '/', '~', '^']:
            # self.type에서 각 연산자를 찾습니다.
            if operator in self.type:
                # 발견되면, self.type을 타입과 연산자 값으로 분리합니다.
                (self.type, self.opvalue) = self.type.split(operator, 1)

                # 지정된 연산자를 기록합니다.
                self.operator = operator

                # 연산자 값을 정수로 변환하려고 시도합니다. 
                # 이 작업은 단순한 연산자 값에 대해서는 작동하지만, 복잡한 타입 (예: '(4.l+12)')에 대해서는 작동하지 않습니다.
                try:
                    self.opvalue = int(self.opvalue, 0)
                except ValueError:
                    pass

                # 한 번에 하나의 연산자만 지원되므로, 발견되면 중지합니다.
                break

        # 지정된 타입이 'u'로 시작하면 (예: 'ubelong'), 부호가 없습니다.
        # 그렇지 않으면 부호가 있는 타입으로 간주됩니다.
        if self.type[0] == 'u':
            self.signed = False
            self.type = self.type[1:]
        else:
            self.signed = True

        # 빅 엔디언 값은 'be'로 시작합니다 ('belong'), 리틀 엔디언 값은 'le'로 시작합니다 ('lelong').
        # struct 모듈은 '>'를 빅 엔디언, '<'를 리틀 엔디언으로 나타냅니다.
        if self.type.startswith('be'):
            self.type = self.type[2:]
            self.endianness = '>'
        elif self.type.startswith('le'):
            self.endianness = '<'
            self.type = self.type[2:]
        # 엔디언이 명시되지 않은 경우 빅 엔디언으로 가정합니다.
        else:
            self.endianness = '>'

        # 타입에 따른 비교 연산자를 확인합니다 (예: '=0x1234', '>0x1234', 등).
        # 연산자가 지정되지 않은 경우, '='가 기본값으로 간주됩니다.
        if parts[2][0] in ['=', '!', '>', '<', '&', '|', '^', '~']:
            self.condition = parts[2][0]
            self.value = parts[2][1:]
        else:
            self.condition = '='
            self.value = parts[2]

        # 와일드카드 값인 경우, self.value를 명시적으로 None으로 설정합니다.
        if self.value == 'x':
            self.value = None
        # 문자열 값은 디코딩이 필요합니다. 이 경우 이스케이프 문자 (예: '\x20')가 포함될 수 있습니다.
        elif self.type == 'string':
            # 문자열 타입은 큰 반복 바이트 시퀀스를 쉽게 일치시키기 위해 곱셈을 지원합니다.
            if '*' in self.value:
                try:
                    p = self.value.split('*')
                    self.value = p[0]
                    for n in p[1:]:
                        self.value *= int(n, 0)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    raise ParserException("문자열 '%s'을(를) 정수 '%s'로 확장하는 데 실패했습니다: '%s'" % (self.value, n, line))
            try:
                self.value = binwalk.core.compat.string_decode(self.value)
            except ValueError:
                raise ParserException("문자열 값 '%s'을(를) 디코드하는 데 실패했습니다: '%s'" % (self.value, line))
        # 정규 표현식이 지정된 경우, 컴파일합니다.
        elif self.type == 'regex':
            self.regex = True

            try:
                self.value = re.compile(self.value)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                raise ParserException("유효하지 않은 정규 표현식 '%s': %s" % (self.value, str(e)))
        # 비 문자열 타입은 정수 값입니다.
        else:
            try:
                self.value = int(self.value, 0)
            except ValueError:
                raise ParserException("값 '%s'을(를) 정수로 변환하는 데 실패했습니다: '%s'" % (self.value, line))

        # 첫 번째 시그니처 라인이 명시적인 값을 가져야 하는지 확인합니다.
        if self.level == 0 and self.value is None:
            raise ParserException("시그니처의 첫 번째 요소는 와일드카드 값이 아닌 명시적인 값을 지정해야 합니다: '%s'" % (line))

        # 지정된 데이터 타입에 대한 크기와 struct 포맷 값을 설정합니다.
        # 이것은 위에서 값이 파싱된 후에 수행되어야 합니다.
        if self.type == 'string':
            # 문자열은 언팩이 필요하지 않으므로 struct 포맷 값이 없습니다.
            self.fmt = None

            # 특정 값이 있는 문자열 타입인 경우, 비교 크기를 해당 문자열의 길이로 설정합니다.
            if self.value:
                self.size = len(self.value)
            # 그렇지 않으면 문자열을 self.MAX_STRING_SIZE로 잘립니다.
            else:
                self.size = self.MAX_STRING_SIZE
        elif self.type == 'regex':
            # 정규 표현식은 언팩이 필요하지 않으므로 struct 포맷 값이 없습니다.
            self.fmt = None
            # 일치하는 정규 표현식의 크기는 데이터가 적용되기 전까지는 알 수 없습니다.
            self.size = self.MAX_STRING_SIZE
        elif self.type == 'byte':
            self.fmt = 'b'
            self.size = 1
        elif self.type == 'short':
            self.fmt = 'h'
            self.size = 2
        elif self.type == 'quad':
            self.fmt = 'q'
            self.size = 8
        # 지원되는 다른 모든 데이터 타입에 대해 4바이트 길이를 가정합니다.
        elif self.type in ['long', 'date']:
            self.fmt = 'i'
            self.size = 4
        else:
            raise ParserException("알 수 없는 데이터 타입 '%s': '%s'" % (self.type, line))

        # struct 모듈은 부호가 있는 데이터 타입을 나타내기 위해 동일한 문자를 사용하지만, 
        # 부호가 있는 데이터 타입은 대문자입니다. 
        # 위의 if-else 코드는 self.fmt를 소문자 (부호가 없는) 값으로 설정합니다.
        if not self.signed:
            self.fmt = self.fmt.upper()

        # struct 포맷이 식별된 경우, 
        # struct.unpack에 전달할 포맷 문자열을 생성하여 엔디언과 데이터 타입 포맷을 지정합니다.
        if self.fmt:
            self.pkfmt = '%c%c' % (self.endianness, self.fmt)
        else:
            self.pkfmt = None

        # 포맷 문자열이 지정되었는지 확인합니다 (이것은 선택 사항입니다).
        if len(parts) == 4:
            # %lld 포맷은 Python이 HAVE_LONG_LONG으로 빌드된 경우에만 지원됩니다.
            self.format = parts[3].replace('%ll', '%l')

            # 태그를 파싱하기 위한 정규 표현식입니다. 태그는 중괄호 안에 포함됩니다.
            retag = re.compile(r'\{.*?\}')

            # 포맷 문자열에서 태그 키워드를 파싱합니다.
            for match in retag.finditer(self.format):
                # 중괄호를 제거합니다.
                tag = match.group().replace('{', '').replace('}', '')

                # 태그가 값을 지정하는 경우, 콜론으로 구분됩니다
                # (예: '{name:%s}').
                if ':' in tag:
                    (n, v) = tag.split(':', 1)
                else:
                    n = tag
                    v = True

                # 새 SignatureTag 인스턴스를 생성하고 self.tags에 추가합니다.
                self.tags[n] = v

            # 출력할 포맷 문자열에서 모든 태그를 제거합니다.
            self.format = retag.sub('', self.format).strip()
        else:
            self.format = ""


class Signature(object):
    '''
    시그니처 데이터를 보유하고 시그니처 정규 표현식을 생성하는 클래스입니다.
    '''

    def __init__(self, sid, first_line):
        '''
        클래스 생성자입니다.

        @sid        - 이 시그니처를 고유하게 식별하기 위한 ID 값.
        @first_line - 시그니처의 첫 번째 SignatureLine (후속 SignatureLine은 self.append를 통해 추가되어야 합니다).

        반환값은 없습니다.
        '''
        self.id = sid
        self.lines = [first_line]
        self.title = first_line.format
        self.offset = first_line.offset
        self.regex = self._generate_regex(first_line)
        try:
            self.confidence = first_line.tags['confidence']
        except KeyError:
            self.confidence = first_line.size

    def _generate_regex(self, line):
        '''
        시그니처의 매직 바이트에서 정규 표현식을 생성합니다.
        이 정규 표현식은 Magic._analyze에서 사용됩니다.

        @line - 시그니처의 첫 번째 SignatureLine 객체.

        컴파일된 정규 표현식을 반환합니다.
        '''
        restr = ""

        # 문자열과 단일 바이트 시그니처는 그대로 사용되며,
        # 다중 바이트 정수 값은 데이터 타입 크기와 엔디언에 따라 정규 표현식 문자열로 변환됩니다.
        if line.type == 'regex':
            # 정규 표현식 타입은 이미 컴파일된 표현식입니다.
            # re.finditer가 사용되므로, 지정된 정규 표현식이 이를 처리하지 않는 한, 중복되는 시그니처는 무시됩니다.
            return line.value
        if line.type == 'string':
            restr = line.value
        elif line.size == 1:
            restr = chr(line.value)
        elif line.size == 2:
            if line.endianness == '<':
                restr = chr(line.value & 0xFF) + chr(line.value >> 8)
            elif line.endianness == '>':
                restr = chr(line.value >> 8) + chr(line.value & 0xFF)
        elif line.size == 4:
            if line.endianness == '<':
                restr = (chr(line.value & 0xFF) +
                         chr((line.value >> 8) & 0xFF) +
                         chr((line.value >> 16) & 0xFF) +
                         chr(line.value >> 24))
            elif line.endianness == '>':
                restr = (chr(line.value >> 24) +
                         chr((line.value >> 16) & 0xFF) +
                         chr((line.value >> 8) & 0xFF) +
                         chr(line.value & 0xFF))
        elif line.size == 8:
            if line.endianness == '<':
                restr = (chr(line.value & 0xFF) +
                         chr((line.value >> 8) & 0xFF) +
                         chr((line.value >> 16) & 0xFF) +
                         chr((line.value >> 24) & 0xFF) +
                         chr((line.value >> 32) & 0xFF) +
                         chr((line.value >> 40) & 0xFF) +
                         chr((line.value >> 48) & 0xFF) +
                         chr(line.value >> 56))
            elif line.endianness == '>':
                restr = (chr(line.value >> 56) +
                         chr((line.value >> 48) & 0xFF) +
                         chr((line.value >> 40) & 0xFF) +
                         chr((line.value >> 32) & 0xFF) +
                         chr((line.value >> 24) & 0xFF) +
                         chr((line.value >> 16) & 0xFF) +
                         chr((line.value >> 8) & 0xFF) +
                         chr(line.value & 0xFF))

        # re.finditer가 시그니처마다 사용되므로, 시그니처는 의도치 않게 중첩되지 않도록 주의 깊게 작성되어야 합니다
        # (예: "ABCDAB" 시그니처는 "ABCDABCDAB" 바이트 시퀀스로 혼동될 수 있습니다). 시그니처가 길수록
        # 의도치 않은 중첩 가능성이 줄어들지만, 파일이 악의적으로 작성되어 거짓 부정 결과를 유발할 수 있습니다.
        #
        # 따라서, 시그니처가 명시적으로 중첩으로 표시되지 않는 한 ('{overlap}'),
        # 중첩되는 시그니처에 대해 경고를 출력합니다.
        if not binwalk.core.compat.has_key(line.tags, 'overlap'):
            for i in range(1, line.size):
                if restr[i:] == restr[0:(line.size - i)]:
                    binwalk.core.common.warning("시그니처 '%s'는 자기 중첩 시그니처입니다!" % line.text)
                    break

        return re.compile(re.escape(restr))

    def append(self, line):
        '''
        새로운 SignatureLine 객체를 시그니처에 추가합니다.

        @line - 새 SignatureLine 인스턴스.

        반환값은 없습니다.
        '''
        # 이 메서드는 현재 쓸모가 없지만, 
        # 향후 코드를 위한 유용한 래퍼가 될 수 있습니다.
        self.lines.append(line)


class Magic(object):
    '''
    시그니처 파일을 로드하고 임의의 데이터 블록에서 일치하는 시그니처를
    스캔하는 주요 클래스입니다.
    '''

    def __init__(self, exclude=[], include=[], invalid=False):
        '''
        클래스 생성자입니다.

        @include - 스캔 결과에 포함할 시그니처를 설명하는 정규 표현식 문자열 목록입니다.
        @exclude - 스캔 결과에 포함하지 않을 시그니처를 설명하는 정규 표현식 문자열 목록입니다.
        @invalid - True로 설정된 경우, 유효하지 않은 결과를 무시하지 않습니다.

        반환값은 없습니다.
        '''
        # self.scan에 전달된 데이터 블록을 저장하는 데 사용됩니다 (self.scan의 추가 설명 참조).
        self.data = ""
        # Signature 클래스 객체의 목록으로, self.parse에 의해 채워집니다 (참조: self.load).
        self.signatures = []
        # 'once' 키워드가 있는 시그니처 중 이미 한 번 표시된 시그니처 목록입니다.
        self.display_once = set()
        self.dirty = True

        self.show_invalid = invalid
        self.includes = [re.compile(x) for x in include]
        self.excludes = [re.compile(x) for x in exclude]

        # 형식화된 시그니처 문자열에서 백스페이스 문자(및 앞의 문자)를 대체하는 정규 표현식 규칙입니다
        # (참조: self._analyze).
        self.bspace = re.compile(".\\\\b")
        # 형식화된 시그니처 문자열에서 출력 가능한 ASCII 문자를 일치시키는 정규 표현식 규칙입니다
        # (참조: self._analyze).
        self.printable = re.compile("[ -~]*")
        # 형식 문자열을 찾기 위한 정규 표현식입니다.
        self.fmtstr = re.compile("%[^%]")
        # 점을 찾기 위한 정규 표현식입니다 (참조: self._do_math).
        self.period = re.compile("\.")

    def reset(self):
        self.display_once = set()

    def _filtered(self, text):
        '''
        문자열이 필터링되어야 하는지 테스트합니다.

        @text - 필터 규칙에 대해 확인할 문자열입니다.

        문자열이 필터링되어 표시되지 않아야 하면 True를 반환합니다.
        표시되어야 하면 False를 반환합니다.
        '''
        filtered = None
        # 텍스트는 먼저 소문자로 변환됩니다. 부분적으로는 역사적인 이유로, 
        # 하지만 필터 규칙을 작성할 때 (예: 대소문자 구분에 대해 걱정하지 않아도 됩니다)
        # 편리하기 때문에 소문자로 변환합니다.
        text = text.lower()

        for include in self.includes:
            if include.search(text):
                filtered = False
                break

        # 독점적인 포함 필터가 지정되고 텍스트와 일치하지 않으면, 텍스트는 필터링되어야 합니다.
        if self.includes and filtered is None:
            return True

        for exclude in self.excludes:
            if exclude.search(text):
                filtered = True
                break

        # 명시적인 제외 필터가 일치하지 않으면, 텍스트는 필터링되지 않아야 합니다.
        if filtered is None:
            filtered = False

        return filtered

    def _do_math(self, offset, expression):
        '''
        복잡한 수식을 파싱하고 평가합니다. 예: "(4.l+12)", "(6*32)", 등.

        @offset      - 현재 시그니처가 시작되는 self.data 내부의 오프셋입니다.
        @expressions - 평가할 표현식입니다.

        평가된 표현식의 결과인 정수 값을 반환합니다.
        '''
        # 표현식에 오프셋이 포함되어 있습니까? (예: "(4.l+12)")
        if '.' in expression and '(' in expression:
            replacements = {}

            for period in [match.start() for match in self.period.finditer(expression)]:
                # 오프셋 필드를 정수 오프셋 및 타입 값 (각각 o와 t)으로 분리합니다.
                s = expression[:period].rfind('(') + 1
                # 오프셋 주소는 평가 가능한 표현식일 수 있으며, 예를 들어 '(4+0.L)'은
                # 원래 오프셋이 '&0.L'과 같은 경우 일반적으로 발생합니다.
                o = binwalk.core.common.MathExpression(expression[s:period]).value
                t = expression[period + 1]

                # 표현식에서 파싱된 오프셋 부분만 다시 작성합니다.
                text = "%s.%c" % (expression[s:period], t)

                # 이 오프셋 표현식을 이미 평가했습니까? 그렇다면 건너뜁니다.
                if binwalk.core.common.has_key(replacements, text):
                    continue

                # 표현식에 지정된 오프셋은 self.data 내부의 시작 오프셋에 상대적입니다.
                o += offset

                # 지정된 오프셋에서 self.data의 값을 읽어옵니다.
                try:
                    # 빅 엔디언 및 리틀 엔디언 바이트 형식
                    if t in ['b', 'B']:
                        v = struct.unpack('b', binwalk.core.compat.str2bytes(self.data[o:o + 1]))[0]
                    # 리틀 엔디언 단축 형식
                    elif t == 's':
                        v = struct.unpack('<h', binwalk.core.compat.str2bytes(self.data[o:o + 2]))[0]
                    # 리틀 엔디언 긴 형식
                    elif t == 'l':
                        v = struct.unpack('<i', binwalk.core.compat.str2bytes(self.data[o:o + 4]))[0]
                    # 빅 엔디언 단축 형식
                    elif t == 'S':
                        v = struct.unpack('>h', binwalk.core.compat.str2bytes(self.data[o:o + 2]))[0]
                    # 빅 엔디언 긴 형식
                    elif t == 'L':
                        v = struct.unpack('>i', binwalk.core.compat.str2bytes(self.data[o:o + 4]))[0]
                # struct.error는 지정된 형식 타입에 대해 self.data에 충분한 바이트가 없는 경우 발생합니다.
                except struct.error:
                    v = 0

                # self.data에서 복구된 모든 값을 추적합니다.
                replacements[text] = v

            # 마지막으로, 모든 오프셋 표현식을 해당 텍스트 값으로 대체합니다.
            v = expression
            for (text, value) in binwalk.core.common.iterator(replacements):
                v = v.replace(text, "%d" % value)

        # 오프셋이 없는 경우, 평가 가능한 수식 (예: "(32+0x20)")입니다.
        else:
            v = expression

        # 최종 표현식을 평가합니다.
        value = binwalk.core.common.MathExpression(v).value

        return value

    def _analyze(self, signature, offset):
        '''
        지정된 오프셋에서 지정된 시그니처 데이터를 분석합니다.

        @signature - 데이터에 적용할 시그니처입니다.
        @offset    - 시그니처를 적용할 self.data의 오프셋입니다.

        데이터에서 파싱된 태그의 딕셔너리를 반환합니다.
        '''
        description = []
        max_line_level = 0
        previous_line_end = 0
        tags = {'id': signature.id, 'offset': offset, 'invalid': False, 'once': False}

        # 지정된 오프셋에서 self.data의 각 시그니처 라인을 적용합니다.
        for n, line in enumerate(signature.lines):

            # 현재 최대 들여쓰기 수준보다 높은 들여쓰기 수준은 무시합니다.
            if line.level <= max_line_level:
                # 시그니처 라인의 상대적 오프셋이 정수 값인 경우 이를 사용합니다.
                if isinstance(line.offset, int):
                    line_offset = line.offset
                # 그렇지 않은 경우, 복잡한 표현식을 평가합니다.
                else:
                    # 이전 라인의 끝 값을 문자열로 포맷합니다. '+' 기호를 추가하여
                    # 이 값이 표현식의 나머지 값에 추가되어야 함을 명시적으로 표시합니다
                    # (예: '&0'이 '4+0'으로 변환됨).
                    ple = '%d+' % previous_line_end
                    # 사용자가 '&0' (libmagic) 또는 '&+0' (명시적 추가) 구문을 사용할 수 있도록 허용합니다.
                    # 둘 다 ple 텍스트로 교체합니다.
                    line_offset_text = line.offset.replace('&+', ple).replace('&', ple)
                    # 표현식을 평가합니다.
                    line_offset = self._do_math(offset, line_offset_text)

                # 유효성 검사
                if not isinstance(line_offset, int):
                    raise ParserException("오프셋 '%s'을(를) 숫자로 변환하는 데 실패했습니다: '%s'" % (line.offset, line.text))

                # 이 라인에서 필요한 데이터의 시작은 offset + line_offset입니다.
                # 데이터의 끝은 line.size 바이트 이후입니다.
                start = offset + line_offset
                end = start + line.size

                # 라인에 패킹된 포맷 문자열이 있는 경우, 이를 언팩합니다.
                if line.pkfmt:
                    try:
                        dvalue = struct.unpack(line.pkfmt, binwalk.core.compat.str2bytes(self.data[start:end]))[0]
                    # self.data에 지정된 포맷 크기에 대해 충분한 바이트가 남아 있지 않음
                    except struct.error:
                        dvalue = 0
                # 그렇지 않으면, 이것은 문자열입니다.
                else:
                    # 와일드카드 문자열의 경우 line.value == None입니다.
                    if line.value is None:
                        # 이 문자열의 크기가 알려져 있고 이전 시그니처 라인에서 지정된 경우 이를 확인합니다.
                        if binwalk.core.compat.has_key(tags, 'strlen') and binwalk.core.compat.has_key(line.tags, 'string'):
                            dvalue = self.data[start:(start + tags['strlen'])]
                        # 그렇지 않으면, 문자열을 첫 번째 줄바꿈, 캐리지 리턴 또는 NULL 바이트에서 종료합니다.
                        else:
                            dvalue = self.data[start:end].split('\x00')[0].split('\r')[0].split('\n')[0]
                    # 비 와일드카드 문자열의 경우, 시그니처 라인에서 지정된 알려진 길이를 가집니다.
                    else:
                        dvalue = self.data[start:end]

                # 일부 정수 값에는 비교를 수행하기 전에 수행해야 하는 특수 연산이 있습니다
                # (예: "belong&0x0000FFFF"). 복잡한 수식도 여기에 지원됩니다.
                # if isinstance(dvalue, int) and line.operator:
                if line.operator:
                    try:
                        # 이 시그니처 라인의 연산자 값이 정수 값인 경우 이를 사용합니다.
                        if isinstance(line.opvalue, int):
                            opval = line.opvalue
                        # 그렇지 않은 경우, 복잡한 표현식을 평가합니다.
                        else:
                            opval = self._do_math(offset, line.opvalue)

                        # 지정된 연산을 수행합니다.
                        if line.operator == '**':
                            dvalue **= opval
                        elif line.operator == '<<':
                            dvalue <<= opval
                        elif line.operator == '>>':
                            dvalue >>= opval
                        elif line.operator == '&':
                            dvalue &= opval
                        elif line.operator == '|':
                            dvalue |= opval
                        elif line.operator == '*':
                            dvalue *= opval
                        elif line.operator == '+':
                            dvalue += opval
                        elif line.operator == '-':
                            dvalue -= opval
                        elif line.operator == '/':
                            dvalue /= opval
                        elif line.operator == '~':
                            dvalue = ~opval
                        elif line.operator == '^':
                            dvalue ^= opval
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        raise ParserException("연산 '" +
                                              str(dvalue) +
                                              " " +
                                              str(line.operator) +
                                              "= " +
                                              str(line.opvalue) +
                                              "' 실패: " + str(e))

                # 데이터 (dvalue)가 지정된 비교와 일치합니까?
                if ((line.value is None) or
                    (line.regex and line.value.match(dvalue)) or
                    (line.condition == '=' and dvalue == line.value) or
                    (line.condition == '>' and dvalue > line.value) or
                    (line.condition == '<' and dvalue < line.value) or
                    (line.condition == '!' and dvalue != line.value) or
                    (line.condition == '~' and (dvalue == ~line.value)) or
                    (line.condition == '^' and (dvalue ^ line.value)) or
                    (line.condition == '&' and (dvalue & line.value)) or
                        (line.condition == '|' and (dvalue | line.value))):

                    # 이 시점까지, 날짜 필드는 정수 값으로 처리되지만,
                    # 이를 멋지게 형식화된 문자열로 표시하고자 합니다.
                    if line.type == 'date':
                        try:
                            ts = datetime.datetime.utcfromtimestamp(dvalue)
                            dvalue = ts.strftime("%Y-%m-%d %H:%M:%S")
                        except KeyboardInterrupt:
                            raise
                        except Exception:
                            dvalue = "잘못된 타임스탬프"

                    # 포맷 문자열에 대한 튜플을 생성합니다.
                    dvalue_tuple = ()
                    for _ in self.fmtstr.finditer(line.format):
                        dvalue_tuple += (dvalue,)

                    # 설명 문자열을 포맷합니다.
                    desc = line.format % dvalue_tuple

                    # 설명 문자열이 있는 경우 이를 설명 문자열 부분 목록에 추가합니다.
                    if desc:
                        description.append(desc)

                    # 시그니처 라인에 지정된 태그 키워드를 처리합니다.
                    # 이 태그들은 원래 포맷 문자열에서 파싱되어 출력된 설명 문자열과 별도로 처리됩니다.
                    for (tag_name, tag_value) in binwalk.core.compat.iterator(line.tags):
                        # 태그 값이 문자열인 경우 이를 포맷하려고 시도합니다.
                        if isinstance(tag_value, str):
                            # 포맷 문자열에 대한 튜플을 생성합니다.
                            dvalue_tuple = ()
                            for _ in self.fmtstr.finditer(tag_value):
                                dvalue_tuple += (dvalue,)

                            # 태그 문자열을 포맷합니다.
                            tags[tag_name] = tag_value % dvalue_tuple
                        # 그렇지 않은 경우, 원시 태그 값을 사용합니다.
                        else:
                            tags[tag_name] = tag_value

                        # 일부 태그 값은 정수 값으로 변환되어야 하므로, 이를 시도합니다.
                        try:
                            tags[tag_name] = int(tags[tag_name], 0)
                        except KeyboardInterrupt:
                            raise
                        except Exception:
                            pass

                    # 이 시그니처가 무효로 표시되면 처리 중단합니다, 
                    # 유효하지 않은 결과가 명시적으로 요청되지 않는 한 처리 중단합니다.
                    # 이는 시그니처에서 잘못된 검사 후 빠르게 스캔하여 거짓 양성 결과를 걸러내는 것을 의미합니다.
                    if not self.show_invalid and tags['invalid']:
                        break

                    # 시그니처의 다음 라인을 미리 봅니다. 
                    # 이 라인의 들여쓰기 수준이 현재 라인보다 높으면, 
                    # 현재 라인의 데이터 끝을 추적합니다. 
                    # 이는 이후 라인에서 '>>&0' 오프셋 구문을 사용하여 이전 라인에서 상대적 오프셋을 지정할 수 있도록 합니다.
                    try:
                        next_line = signature.lines[n + 1]
                        if next_line.level > line.level:
                            if line.type == 'string':
                                previous_line_end = line_offset + len(dvalue)
                            else:
                                previous_line_end = line_offset + line.size
                    except IndexError:
                        pass

                    # 이 라인이 비교를 만족했다면, 최대 들여쓰기 수준을 +1 합니다.
                    max_line_level = line.level + 1
                else:
                    # 첫 번째 라인에서 일치하지 않으면 중단합니다.
                    if line.level == 0:
                        break
                    else:
                        # 이 라인이 비교를 만족하지 않았다면, 더 높은 들여쓰기 수준은 허용되지 않습니다.
                        max_line_level = line.level

        # 형식화된 설명 문자열을 결합하고 백스페이스 문자 (및 앞의 문자)를 제거합니다.
        tags['description'] = self.bspace.sub('', " ".join(description))

        # 이것은 절대 발생해서는 안 됩니다.
        if not tags['description']:
            tags['display'] = False
            tags['invalid'] = True

        # 형식화된 문자열에 출력할 수 없는 문자가 포함된 경우, 이를 무효로 간주합니다.
        if self.printable.match(tags['description']).group() != tags['description']:
            tags['invalid'] = True

        return tags

    def match(self, data):
        '''
        데이터 버퍼의 시작 부분과 시그니처를 일치시킵니다.

        @data - 로드된 시그니처 목록과 일치시킬 데이터 버퍼.

        SignatureResult 객체 목록을 반환합니다.
        '''
        return self.scan(data, 1)

    def scan(self, data, dlen=None):
        '''
        데이터 블록에서 일치하는 시그니처를 스캔합니다.

        @data - 스캔할 데이터 문자열입니다.
        @dlen - 지정된 경우, 이 값을 초과하는 오프셋에서 시그니처를 무시합니다.

        SignatureResult 객체 목록을 반환합니다.
        '''
        results = []
        matched_offsets = set()

        # 데이터는 잠재적으로 매우 클 수 있으므로, 이를 클래스 속성을 통해 사용할 수 있도록 하여
        # 다른 메서드에 전달되지 않도록 합니다.
        self.data = data

        # dlen이 지정되지 않은 경우, self.data 전체를 검색합니다.
        if dlen is None:
            dlen = len(data)

        for signature in self.signatures:
            # 정규 표현식을 사용하여 데이터 블록에서 잠재적인 시그니처 일치를 검색합니다 (빠름).
            for match in signature.regex.finditer(data):
                # 시그니처의 시작 오프셋을 고려합니다.
                offset = match.start() - signature.offset

                # 시그니처는 매직 바이트 길이에 따라 정렬됩니다 (가장 긴 것부터).
                # 이 오프셋이 이전 시그니처와 이미 일치한 경우, 
                # self.show_invalid이 지정되지 않는 한 이를 무시합니다. 
                # 또한 명백히 유효하지 않은 오프셋 (<0) 및 self.data 범위 (dlen) 밖의 오프셋도 무시합니다.
                if (offset not in matched_offsets or self.show_invalid) and 0 <= offset < dlen:
                    # 이 오프셋에서 현재 시그니처 규칙을 사용하여 데이터를 분석합니다.
                    tags = self._analyze(signature, offset)

                    # 시그니처가 유효하거나 유효하지 않은 결과가 요청된 경우, SignatureResult 객체를 생성하여 결과 목록에 추가합니다.
                    if (not tags['invalid'] or self.show_invalid) and not self._filtered(tags['description']):
                        # 'once' 태그가 있는 결과는 한 번만 표시합니다.
                        if tags['once']:
                            if signature.title in self.display_once:
                                continue
                            else:
                                self.display_once.add(signature.title)

                        # 결과를 결과 목록에 추가합니다.
                        results.append(SignatureResult(**tags))

                        # 이 오프셋을 matched_offsets 세트에 추가하여, 이후 루프에서 무시되도록 합니다.
                        matched_offsets.add(offset)

        # 결과를 오프셋 순서로 정렬합니다.
        results.sort(key=lambda x: x.offset, reverse=False)

        return results

    def load(self, fname):
        '''
        파일에서 시그니처를 로드합니다.

        @fname - 시그니처 파일의 경로.

        반환값은 없습니다.
        '''
        # 매직 파일은 ASCII여야 하며, 그렇지 않으면 인코딩 문제가 발생할 수 있습니다.
        with open(fname, "r") as fp:
            lines = fp.readlines()
        self.parse(lines)

    def parse(self, lines):
        '''
        시그니처 파일의 라인을 파싱합니다.

        @lines - 시그니처 파일의 라인 목록.

        반환값은 없습니다.
        '''
        signature = None

        for line in lines:
            # 첫 번째 주석 구분자에서 라인을 분할하고 결과를 제거합니다.
            line = line.split('#')[0].strip()
            # 빈 줄과 주석으로만 구성된 줄을 무시합니다.
            # 우리는 '!mime' 스타일 라인 항목을 지원하지 않습니다.
            if line and line[0] != '!':
                # 이 시그니처 라인을 파싱합니다.
                sigline = SignatureLine(line)
                # 레벨 0은 시그니처 항목의 첫 번째 라인을 의미합니다.
                if sigline.level == 0:
                    # 기존 시그니처가 있고, 그 텍스트가 사용자 정의 필터 규칙에 의해 필터링되지 않은 경우,
                    # 이를 시그니처 목록에 추가합니다.
                    if signature and not self._filtered(signature.title):
                        self.signatures.append(signature)

                    # 새 시그니처 객체를 생성합니다. 
                    # self.signatures의 크기를 사용하여 각 시그니처에 고유한 ID를 할당합니다.
                    signature = Signature(len(self.signatures), sigline)
                # 그렇지 않은 경우, 이 라인을 기존 시그니처에 추가합니다.
                elif signature:
                    signature.lines.append(sigline)
                # 이것이 시그니처 항목의 첫 번째 라인이 아니며, 다른 기존 시그니처 항목이 없는 경우,
                # 시그니처 파일에 문제가 있는 것입니다.
                else:
                    raise ParserException("잘못된 시그니처 라인: '%s'" % line)

        # 마지막 시그니처를 시그니처 목록에 추가합니다.
        if signature and not self._filtered(signature.lines[0].format):
            self.signatures.append(signature)

        # 시그니처를 신뢰도(즉, 매직 바이트 길이)에 따라 정렬합니다. 가장 긴 것부터.
        self.signatures.sort(key=lambda x: x.confidence, reverse=True)
