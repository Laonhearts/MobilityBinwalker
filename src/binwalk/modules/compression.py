# 다양한 압축 알고리즘(현재는 주로 Deflate)의 원시 압축 해제를 수행하는 모듈
import os
import zlib
import struct
import binwalk.core.compat
import binwalk.core.common
from binwalk.core.module import Option, Kwarg, Module

try:

    import lzma

except ImportError:

    from backports import lzma  # lzma 모듈이 없는 경우 대체 라이브러리 사용

class LZMAHeader(object):   # LZMA 헤더 정보를 저장하는 클래스

    def __init__(self, **kwargs):

        for (k, v) in binwalk.core.compat.iterator(kwargs):

            setattr(self, k, v)

class LZMA(object):    # LZMA 압축 스트림을 처리하는 클래스

    DESCRIPTION = "Raw LZMA compression stream"
    COMMON_PROPERTIES = [0x5D, 0x6E]
    MAX_PROP = ((4 * 5 + 4) * 9 + 8)
    BLOCK_SIZE = 32 * 1024

    def __init__(self, module):

        self.module = module
        self.properties = None

        self.build_properties()
        self.build_dictionaries()
        self.build_headers()

        # 추출 규칙 추가
        if self.module.extractor.enabled:

            self.module.extractor.add_rule(regex='^%s' % self.DESCRIPTION.lower(), extension="7z", cmd=self.extractor)

    def extractor(self, file_name):
        
        # 압축된 데이터를 포함하는 파일을 열고 읽습니다.
        compressed_data = binwalk.core.common.BlockFile(file_name).read()

        # 속성 감지를 위해 압축 해제 시도
        if self.decompress(compressed_data[:self.BLOCK_SIZE]):

            # LZMA 헤더를 생성하고 원시 압축 데이터 상단에 추가한 후 디스크에 다시 씁니다.
            header = chr(self.properties) + \
                     self.dictionaries[-1] + ("\xFF" * 8)
            binwalk.core.common.BlockFile(file_name, "wb").write(header + compressed_data)

            # 정상적으로 압축 해제될 때까지 모든 LZMA 추출기를 시도합니다.
            for exrule in self.module.extractor.match("lzma compressed data"):

                if self.module.extractor.execute(exrule['cmd'], file_name):
                
                    break

    def build_property(self, pb, lp, lc):   # LZMA 속성을 계산하는 함수

        prop = (((pb * 5) + lp) * 9) + lc
    
        if prop > self.MAX_PROP:
    
            return None
    
        return int(prop)

    def parse_property(self, prop):     # LZMA 속성을 파싱하는 함수

        prop = int(ord(prop))

        if prop > self.MAX_PROP:
    
            return None

        pb = prop // (9 * 5)
        prop -= pb * 9 * 5
        lp = prop // 9
        lc = prop - lp * 9

        return (pb, lp, lc)

    def parse_header(self, header):     # LZMA 헤더를 파싱하여 속성 정보를 반환

        (pb, lp, lc) = self.parse_property(header[0])
    
        dictionary = struct.unpack("<I", binwalk.core.compat.str2bytes(header[1:5]))[0]
    
        return LZMAHeader(pb=pb, lp=lp, lc=lc, dictionary=dictionary)

    def build_properties(self):
        
        # LZMA 속성 목록을 생성
        self.properties = set()

        if self.module.partial_scan:
        
            # 부분 스캔의 경우, 가장 일반적인 속성만 확인
            for prop in self.COMMON_PROPERTIES:
        
                self.properties.add(chr(prop))
        else:
        
            for pb in range(0, 9):
        
                for lp in range(0, 5):
        
                    for lc in range(0, 5):
        
                        prop = self.build_property(pb, lp, lc)
        
                        if prop is not None:
        
                            self.properties.add(chr(prop))

    def build_dictionaries(self):
        
        # LZMA 사전 목록을 생성
        self.dictionaries = []

        if self.module.partial_scan:
        
            # 부분 스캔의 경우, 가장 큰 사전 값만 사용
            self.dictionaries.append(binwalk.core.compat.bytes2str(struct.pack("<I", 2 ** 25)))
        
        else:
        
            for n in range(16, 26):
        
                self.dictionaries.append(binwalk.core.compat.bytes2str(struct.pack("<I", 2 ** n)))

    def build_headers(self):
        
        # LZMA 헤더 목록을 생성
        self.headers = set()

        for prop in self.properties:
        
            for dictionary in self.dictionaries:
        
                self.headers.add(prop + dictionary + ("\xFF" * 8))

    def decompress(self, data):
        
        # LZMA 데이터를 압축 해제하고, 결과를 설명 문자열로 반환
        result = None
        description = None

        for header in self.headers:
        
            try:
        
                final_data = binwalk.core.compat.str2bytes(header + data)
        
                lzma.decompress(final_data)
        
                result = self.parse_header(header)
        
                break
        
            except IOError as e:
        
                if str(e) == "unknown BUF error":
        
                    result = self.parse_header(header)
        
                    break
        
            except Exception as e:
        
                if str(e) == "Compressed data ended before the end-of-stream marker was reached":
        
                    result = self.parse_header(header)
        
                    break

        if result is not None:
        
            self.properties = self.build_property(result.pb, result.lp, result.lc)
        
            description = "%s, properties: 0x%.2X [pb: %d, lp: %d, lc: %d], dictionary size: %d" % (
                self.DESCRIPTION, self.properties, result.pb, result.lp, result.lc, result.dictionary)

        return description

class Deflate(object):  # Deflate 압축 스트림을 처리하는 클래스

    DESCRIPTION = "Raw deflate compression stream"
    BLOCK_SIZE = 33 * 1024

    def __init__(self, module):

        self.module = module

        # 추출 규칙 추가
        if self.module.extractor.enabled:

            self.module.extractor.add_rule(regex='^%s' % self.DESCRIPTION.lower(), extension="deflate", cmd=self.extractor)

    def extractor(self, file_name):

        # 파일을 열고, Deflate 압축을 해제합니다.
        in_data = ""
        out_data = ""
        retval = False
        out_file = os.path.splitext(file_name)[0]

        with binwalk.core.common.BlockFile(file_name, 'r') as fp_in:
        
            while True:
        
                (data, dlen) = fp_in.read_block()
        
                if not data or dlen == 0:
        
                    break
        
                else:
        
                    in_data += data[:dlen]

                try:
        
                    out_data = zlib.decompress(binwalk.core.compat.str2bytes(in_data), -15)
        
                    with binwalk.core.common.BlockFile(out_file, 'w') as fp_out:
        
                        fp_out.write(out_data)
        
                    retval = True
        
                    break
        
                except zlib.error:
        
                    pass

        return retval

    def decompress(self, data):
        
        # Deflate 데이터를 압축 해제하고, 결과를 설명 문자열로 반환
        try:
        
            zlib.decompress(binwalk.core.compat.str2bytes(data), -15)
        
        except zlib.error as e:
        
            if not str(e).startswith("Error -5"):
        
                return None

        return self.DESCRIPTION

class RawCompression(Module):   # 원시 압축 해제를 수행하는 모듈

    TITLE = 'Raw Compression'

    CLI = [
        Option(short='X',
               long='deflate',
               kwargs={'enabled': True, 'scan_for_deflate': True},
               description='Deflate 압축 스트림을 스캔'),
        Option(short='Z',
               long='lzma',
               kwargs={'enabled': True, 'scan_for_lzma': True},
               description='LZMA 압축 스트림을 스캔'),
        Option(short='P',
               long='partial',
               kwargs={'partial_scan': True},
               description='부분 스캔을 수행하여 속도를 높임'),
        Option(short='S',
               long='stop',
               kwargs={'stop_on_first_hit': True},
               description='첫 번째 결과에서 중지'),
    ]

    KWARGS = [
        Kwarg(name='enabled', default=False),
        Kwarg(name='partial_scan', default=False),
        Kwarg(name='stop_on_first_hit', default=False),
        Kwarg(name='scan_for_deflate', default=False),
        Kwarg(name='scan_for_lzma', default=False),
    ]

    def init(self):

        # 모듈 초기화 시 압축 해제기를 설정
        self.decompressors = []

        if self.scan_for_deflate:
        
            self.decompressors.append(Deflate(self))
        if self.scan_for_lzma:
        
            self.decompressors.append(LZMA(self))

    def run(self):
        
        # 파일을 읽고 압축 해제를 시도
        for fp in iter(self.next_file, None):
        
            file_done = False
        
            self.header()

            while not file_done:
        
                (data, dlen) = fp.read_block()
        
                if dlen < 1:
        
                    break

                for i in range(0, dlen):
        
                    for decompressor in self.decompressors:
        
                        description = decompressor.decompress(data[i:i + decompressor.BLOCK_SIZE])
        
                        if description:
        
                            self.result(description=description, file=fp, offset=fp.tell() - dlen + i)
        
                            if self.stop_on_first_hit:
        
                                file_done = True
        
                                break

                    if file_done:
        
                        break

                    self.status.completed += 1

                self.status.completed = fp.tell() - fp.offset

            self.footer()
