import capstone
import binwalk.core.common
import binwalk.core.compat
from binwalk.core.module import Module, Option, Kwarg

class ArchResult(object):   # 아키텍처 분석 결과를 저장하는 클래스
    
    def __init__(self, **kwargs):
        
        for (k, v) in binwalk.core.compat.iterator(kwargs):
        
            setattr(self, k, v)

class Architecture(object):     # 지원되는 CPU 아키텍처 정보를 저장하는 클래스

    def __init__(self, **kwargs):

        for (k, v) in binwalk.core.compat.iterator(kwargs):

            setattr(self, k, v)

class Disasm(Module):   # Disasm 클래스는 파일에서 CPU 아키텍처를 식별하기 위해 Capstone 디스어셈블러를 사용하는 모듈입니다.
    
    THRESHOLD = 10  # 유효한 명령어 시퀀스를 판단하는 임계값
    DEFAULT_MIN_INSN_COUNT = 500  # 기본 최소 명령어 수

    TITLE = "Disassembly Scan"  # 모듈 제목
    ORDER = 10  # 모듈 실행 순서

    # 명령줄 인터페이스 옵션 설정
    CLI = [
        Option(short='Y',
               long='disasm',
               kwargs={'enabled': True},
               description='Capstone 디스어셈블러를 사용하여 파일의 CPU 아키텍처 식별'),
        Option(short='T',
               long='minsn',
               type=int,
               kwargs={'min_insn_count': 0},
               description='유효한 명령어로 간주되는 최소 명령어 수 설정 (기본값: %d)' % DEFAULT_MIN_INSN_COUNT),
        Option(long='continue',
               short='k',
               kwargs={'keep_going': True},
               description="첫 번째 매치에서 멈추지 않고 계속 진행"),
    ]

    # 클래스 초기화 시 사용할 기본 값들
    KWARGS = [
        Kwarg(name='enabled', default=False),
        Kwarg(name='keep_going', default=False),
        Kwarg(name='min_insn_count', default=DEFAULT_MIN_INSN_COUNT),
    ]

    # 지원되는 아키텍처 목록
    ARCHITECTURES = [
        Architecture(type=capstone.CS_ARCH_ARM,
                     mode=capstone.CS_MODE_ARM,
                     endianness=capstone.CS_MODE_BIG_ENDIAN,
                     description="ARM 실행 코드, 32비트, 빅 엔디안"),
        Architecture(type=capstone.CS_ARCH_ARM,
                     mode=capstone.CS_MODE_ARM,
                     endianness=capstone.CS_MODE_LITTLE_ENDIAN,
                     description="ARM 실행 코드, 32비트, 리틀 엔디안"),
        Architecture(type=capstone.CS_ARCH_ARM64,
                     mode=capstone.CS_MODE_ARM,
                     endianness=capstone.CS_MODE_BIG_ENDIAN,
                     description="ARM 실행 코드, 64비트, 빅 엔디안"),
        Architecture(type=capstone.CS_ARCH_ARM64,
                     mode=capstone.CS_MODE_ARM,
                     endianness=capstone.CS_MODE_LITTLE_ENDIAN,
                     description="ARM 실행 코드, 64비트, 리틀 엔디안"),
        Architecture(type=capstone.CS_ARCH_PPC,
                     mode=capstone.CS_MODE_BIG_ENDIAN,
                     endianness=capstone.CS_MODE_BIG_ENDIAN,
                     description="PPC 실행 코드, 32/64비트, 빅 엔디안"),
        Architecture(type=capstone.CS_ARCH_MIPS,
                     mode=capstone.CS_MODE_64,
                     endianness=capstone.CS_MODE_BIG_ENDIAN,
                     description="MIPS 실행 코드, 32/64비트, 빅 엔디안"),
        Architecture(type=capstone.CS_ARCH_MIPS,
                     mode=capstone.CS_MODE_64,
                     endianness=capstone.CS_MODE_LITTLE_ENDIAN,
                     description="MIPS 실행 코드, 32/64비트, 리틀 엔디안"),
        Architecture(type=capstone.CS_ARCH_ARM,
                     mode=capstone.CS_MODE_THUMB,
                     endianness=capstone.CS_MODE_LITTLE_ENDIAN,
                     description="ARM 실행 코드, 16비트 (Thumb), 리틀 엔디안"),
        Architecture(type=capstone.CS_ARCH_ARM,
                     mode=capstone.CS_MODE_THUMB,
                     endianness=capstone.CS_MODE_BIG_ENDIAN,
                     description="ARM 실행 코드, 16비트 (Thumb), 빅 엔디안"),
    ]

    def init(self):    # 초기화 함수: 디스어셈블러 설정
        
        self.disassemblers = []

        if not self.min_insn_count:
        
            self.min_insn_count = self.DEFAULT_MIN_INSN_COUNT

        self.disasm_data_size = self.min_insn_count * 10

        for arch in self.ARCHITECTURES:
        
            self.disassemblers.append((capstone.Cs(arch.type, (arch.mode + arch.endianness)), arch.description))

    def scan_file(self, fp):    # 파일을 스캔하여 유효한 명령어 시퀀스를 찾는 함수
        
        total_read = 0

        while True:

            result = None

            (data, dlen) = fp.read_block()
            
            if dlen < 1:
            
                break

            # 데이터 블록이 최소 두 개 이상의 다른 바이트를 포함하지 않으면 건너뜁니다.
            # 이는 잘못된 결과를 방지하기 위함입니다.
            if len(set(data)) >= 2:
            
                block_offset = 0

                while (block_offset < dlen) and (result is None or result.count < self.THRESHOLD):
            
                    # 대규모 데이터 블록을 효율적으로 처리하기 위해 작은 코드 블록으로 나눕니다.
            
                    code_block = binwalk.core.compat.str2bytes(data[block_offset:block_offset + self.disasm_data_size])

                    if len(set(code_block)) >= 2:
            
                        for (md, description) in self.disassemblers:
            
                            insns = [insn for insn in md.disasm_lite(code_block, (total_read + block_offset))]
            
                            binwalk.core.common.debug("0x%.8X   %s, 적어도 %d개의 유효한 명령어" % ((total_read + block_offset),
                                                                                 description,
                                                                                 len(insns)))

                            # 최소 self.min_insn_count 만큼의 명령어를 디스어셈블 했는지 확인
                            if len(insns) >= self.min_insn_count:
            
                                if result and result.description == description:
            
                                    result.count += 1
            
                                    if result.count >= self.THRESHOLD:
            
                                        break
            
                                else:
            
                                    result = ArchResult(offset=total_read +
                                        block_offset + fp.offset,
                                        description=description,
                                        insns=insns,
                                        count=1)

                    block_offset += 1
            
                    self.status.completed += 1

                if result is not None:
            
                    r = self.result(offset=result.offset,
                                    file=fp,
                                    description=(result.description + ", 적어도 %d개의 유효한 명령어" % len(result.insns)))

                    if r.valid and r.display:
            
                        if self.config.verbose:
            
                            for (position, size, mnem, opnds) in result.insns:
            
                                self.result(offset=position, file=fp, description="%s %s" % (mnem, opnds))
            
                        if not self.keep_going:
            
                            return

            total_read += dlen
            
            self.status.completed = total_read

    def run(self):  # 모듈 실행 시 호출되는 메인 함수
        
        for fp in iter(self.next_file, None):
        
            self.header()
            self.scan_file(fp)
            self.footer()
