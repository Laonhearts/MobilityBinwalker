# 기본 서명 스캔 모듈입니다. binwalk의 기본 (주요) 기능입니다.
import binwalk.core.magic
from binwalk.core.module import Module, Option, Kwarg

class Signature(Module):

    TITLE = "Signature Scan"  # 모듈의 제목
    ORDER = 10  # 모듈 실행 순서

    # 명령줄 인터페이스 옵션 설정
    CLI = [
        Option(short='B',
               long='signature',
               kwargs={'enabled': True, 'explicit_signature_scan': True},
               description='대상 파일에서 일반적인 파일 서명을 스캔'),
        Option(short='R',
               long='raw',
               kwargs={'enabled': True, 'raw_bytes': []},
               type=list,
               dtype=str.__name__,
               description='지정된 바이트 시퀀스에 대해 대상 파일을 스캔'),
        Option(short='A',
               long='opcodes',
               kwargs={'enabled': True, 'search_for_opcodes': True},
               description='일반적인 실행 파일 opcode 서명을 스캔'),
        Option(short='m',
               long='magic',
               kwargs={'enabled': True, 'magic_files': []},
               type=list,
               dtype='file',
               description='사용할 사용자 정의 magic 파일을 지정'),
        Option(short='b',
               long='dumb',
               kwargs={'dumb_scan': True},
               description='스마트 서명 키워드를 비활성화'),
        Option(short='I',
               long='invalid',
               kwargs={'show_invalid': True},
               description='유효하지 않은 것으로 표시된 결과를 표시'),
        Option(short='x',
               long='exclude',
               kwargs={'exclude_filters': []},
               type=list,
               dtype=str.__name__,
               description='지정된 문자열과 일치하는 결과를 제외'),
        Option(short='y',
               long='include',
               kwargs={'include_filters': []},
               type=list,
               dtype=str.__name__,
               description='지정된 문자열과 일치하는 결과만 표시'),
    ]

    # 클래스 초기화 시 사용할 기본 값들
    KWARGS = [
        Kwarg(name='enabled', default=False),
        Kwarg(name='show_invalid', default=False),
        Kwarg(name='include_filters', default=[]),
        Kwarg(name='exclude_filters', default=[]),
        Kwarg(name='raw_bytes', default=[]),
        Kwarg(name='search_for_opcodes', default=False),
        Kwarg(name='explicit_signature_scan', default=False),
        Kwarg(name='dumb_scan', default=False),
        Kwarg(name='magic_files', default=[]),
    ]

    VERBOSE_FORMAT = "%s    %d"  # 자세한 출력 형식

    def init(self):
        self.one_of_many = None  # 여러 서명이 반복되는 것을 방지하는 플래그

        # 사용자의 magic 파일을 먼저 추가하여 해당 서명이 우선 적용되도록 설정
        if self.search_for_opcodes:
            self.magic_files = [
                self.config.settings.user.binarch,
                self.config.settings.system.binarch,
            ]

        # 시스템 기본 magic 파일 사용 설정
        if (not self.magic_files and not self.raw_bytes) or self.explicit_signature_scan:
            self.magic_files += self.config.settings.user.magic + \
                self.config.settings.system.magic

        # libmagic 초기화
        self.magic = binwalk.core.magic.Magic(include=self.include_filters,
                                              exclude=self.exclude_filters,
                                              invalid=self.show_invalid)

        # 지정된 바이트 시퀀스에서 서명을 생성
        if self.raw_bytes:
            raw_signatures = []
            for raw_bytes in self.raw_bytes:
                raw_signatures.append("0    string    %s    Raw signature (%s)" % (raw_bytes, raw_bytes))
            binwalk.core.common.debug("Parsing raw signatures: %s" % str(raw_signatures))
            self.magic.parse(raw_signatures)

        # magic 파일을 파싱
        if self.magic_files:
            binwalk.core.common.debug("Loading magic files: %s" % str(self.magic_files))
            for f in self.magic_files:
                self.magic.load(f)

        self.VERBOSE = ["Signatures:", len(self.magic.signatures)]

    def validate(self, r):
        '''
        self.result에 의해 자동으로 호출됩니다.
        '''
        if self.show_invalid:
            r.valid = True
        elif r.valid:
            if not r.description:
                r.valid = False

            if r.size and (r.size + r.offset) > r.file.size:
                r.valid = False

            if r.jump and (r.jump + r.offset) > r.file.size:
                r.valid = False

            if hasattr(r, "location") and (r.location != r.offset):
                r.valid = False

        if r.valid:
            # 여러 번 반복되는 서명 (예: JFFS2 노드)을 반복적으로 표시하지 않음
            if r.id == self.one_of_many:
                r.display = False
            elif r.many:
                self.one_of_many = r.id
            else:
                self.one_of_many = None

    def scan_file(self, fp):
        # 파일을 스캔하여 서명을 인식하는 함수
        self.one_of_many = None
        self.magic.reset()

        while True:
            (data, dlen) = fp.read_block()
            if dlen < 1:
                break

            current_block_offset = 0
            block_start = fp.tell() - dlen
            self.status.completed = block_start - fp.offset

            # 이 데이터 블록을 서명으로 스캔
            for r in self.magic.scan(data, dlen):
                if r.offset < current_block_offset:
                    continue

                relative_offset = r.offset + r.adjust

                r.offset = block_start + relative_offset

                r.file = fp

                self.result(r=r)

                if r.end == True:
                    r.jump = fp.size

                if r.valid and r.jump > 0 and not self.dumb_scan:
                    absolute_jump_offset = r.offset + r.jump
                    current_block_offset = relative_offset + r.jump

                    if absolute_jump_offset >= fp.tell():
                        fp.seek(r.offset + r.jump)
                        break

    def run(self):
        # 모듈 실행 시 호출되는 메인 함수
        for fp in iter(self.next_file, None):
            self.header()
            self.scan_file(fp)
            self.footer()
