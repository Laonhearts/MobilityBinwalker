import io
import os
import logging


class ShutUpHashlib(logging.Filter):

    '''
    IDA와 함께 번들된 Python 인터프리터를 사용할 때
    발생하는 hashlib 예외 메시지를 억제하는 클래스입니다.
    '''

    def filter(self, record):
        return not record.getMessage().startswith("code for hash")

try:
    import idc
    import idaapi
    LOADED_IN_IDA = True
    logger = logging.getLogger()
    logger.addFilter(ShutUpHashlib())
except ImportError:
    LOADED_IN_IDA = False


def start_address():
    # 첫 번째 세그먼트의 시작 주소를 반환합니다.
    return idaapi.get_first_seg().startEA


def end_address():
    # 모든 세그먼트를 순회하며 마지막 세그먼트의 끝 주소를 반환합니다.
    last_ea = idc.BADADDR
    seg = idaapi.get_first_seg()

    while seg:
        last_ea = seg.endEA
        seg = idaapi.get_next_seg(last_ea)

    return last_ea


class IDBFileIO(io.FileIO):

    '''
    binwalk.core.common.Blockfile을 오버라이드하여
    원본 파일 대신 IDB(IDA 데이터베이스)에서 데이터를 읽는 커스텀 클래스입니다.

    현재 IDB가 아닌 파일에 대한 읽기 요청은 상위 io.FileIO 클래스에서 처리됩니다.
    '''

    def __init__(self, fname, mode):
        if idc.GetIdbPath() != fname:
            # IDB가 아닌 파일인 경우, 일반 파일로 처리합니다.
            self.__idb__ = False
            super(IDBFileIO, self).__init__(fname, mode)
        else:
            # IDB 파일인 경우, IDB에서 데이터를 읽도록 설정합니다.
            self.__idb__ = True
            self.name = fname

            self.idb_start = 0
            self.idb_pos = 0
            self.idb_end = end_address()

            if self.args.size == 0:
                self.args.size = end_address()

            if self.args.offset == 0:
                self.args.offset = start_address()
            elif self.args.offset < 0:
                self.args.length = self.args.offset * -1
                self.args.offset = end_address() + self.args.offset

            if self.args.length == 0 or self.args.length > (end_address() - start_address()):
                self.args.length = end_address() - start_address()

    def read(self, n=-1):
        if not self.__idb__:
            # IDB가 아닌 파일의 경우, 상위 클래스의 read 메서드를 호출합니다.
            return super(IDBFileIO, self).read(n)
        else:
            data = ''
            read_count = 0
            filler_count = 0

            # IDB의 세그먼트에서 n 바이트를 읽어오며, 세그먼트 간의 빈 공간은 NULL 바이트로 채웁니다.
            while n and self.idb_pos <= self.idb_end:
                segment = idaapi.getseg(self.idb_pos)

                if not segment:
                    filler_count += 1
                    self.idb_pos += 1
                    n -= 1
                else:
                    if filler_count:
                        data += "\x00" * filler_count
                        filler_count = 0

                    if (self.idb_pos + n) > segment.endEA:
                        read_count = segment.endEA - self.idb_pos
                    else:
                        read_count = n

                    try:
                        data += idc.GetManyBytes(self.idb_pos, read_count)
                    except TypeError as e:
                        # 초기화되지 않은 세그먼트에서 읽으려고 할 때 발생하는 예외를 처리합니다.
                        data += "\x00" * read_count

                    n -= read_count
                    self.idb_pos += read_count

            if filler_count:
                data += "\x00" * filler_count
                filler_count = 0

            return data

    def write(self, data):
        if not self.__idb__:
            # IDB가 아닌 경우, 상위 클래스의 write 메서드를 호출합니다.
            return super(IDBFileIO, self).write(data)
        else:
            # IDB에는 실제로 쓰기를 하지 않으며, 쓰기 요청된 바이트 수를 반환합니다.
            return len(data)

    def seek(self, n, whence=os.SEEK_SET):
        if not self.__idb__:
            # IDB가 아닌 경우, 상위 클래스의 seek 메서드를 호출합니다.
            return super(IDBFileIO, self).seek(n, whence)
        else:
            # IDB의 특정 위치로 이동합니다.
            if whence == os.SEEK_SET:
                self.idb_pos = self.idb_start + n
            elif whence == os.SEEK_CUR:
                self.idb_pos += n
            elif whence == os.SEEK_END:
                self.idb_pos = self.idb_end + n

    def tell(self):
        if not self.__idb__:
            # IDB가 아닌 경우, 상위 클래스의 tell 메서드를 호출합니다.
            return super(IDBFileIO, self).tell()
        else:
            # 현재 IDB의 위치를 반환합니다.
            return self.idb_pos
