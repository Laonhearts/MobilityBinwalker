import os
import errno
import struct
import binwalk.core.common
import binwalk.core.compat
import binwalk.core.plugin

class PFSCommon(object):
    """
    PFS 파일 시스템과 관련된 공통 작업을 처리하는 클래스.
    """

    def _make_short(self, data, endianness):
        """
        2바이트 정수를 반환합니다.
        """
        data = binwalk.core.compat.str2bytes(data)
        return struct.unpack('%sH' % endianness, data)[0]

    def _make_int(self, data, endianness):
        """
        4바이트 정수를 반환합니다.
        """
        data = binwalk.core.compat.str2bytes(data)
        return struct.unpack('%sI' % endianness, data)[0]

class PFS(PFSCommon):
    """
    PFS 파일 시스템의 메타 데이터를 접근하기 위한 클래스.
    """
    HEADER_SIZE = 16

    def __init__(self, fname, endianness='<'):
        self.endianness = endianness
        self.meta = binwalk.core.common.BlockFile(fname, 'rb')
        header = self.meta.read(self.HEADER_SIZE)
        self.file_list_start = self.meta.tell()

        # 파일 수를 읽어옴
        self.num_files = self._make_short(header[-2:], endianness)
        # 노드의 크기를 계산
        self.node_size = self._get_fname_len() + 12

    def _get_fname_len(self, bufflen=128):
        """
        파일 이름에 할당된 바이트 수를 반환합니다.
        """
        buff = self.meta.peek(bufflen)
        strlen = buff.find('\0')
        for i, b in enumerate(buff[strlen:]):
            if b != '\0':
                return strlen+i
        return bufflen

    def _get_node(self):
        """
        메타 데이터에서 하나의 PFS 노드를 읽고 반환합니다.
        """
        data = self.meta.read(self.node_size)
        return PFSNode(data, self.endianness)

    def get_end_of_meta_data(self):
        """
        파일 시스템 메타 데이터의 끝 위치를 반환합니다.
        """
        return self.HEADER_SIZE + self.node_size * self.num_files

    def entries(self):
        """
        파일 메타 데이터 항목을 하나씩 반환합니다.
        """
        self.meta.seek(self.file_list_start)
        for i in range(0, self.num_files):
            yield self._get_node()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.meta.close()

class PFSNode(PFSCommon):
    """
    PFS 파일 시스템 내의 하나의 파일에 대한 메타 데이터를 포함하는 노드 클래스.
    """

    def __init__(self, data, endianness):
        self.fname, data = data[:-12], data[-12:]
        self._decode_fname()  # 파일 이름을 디코딩
        self.inode_no = self._make_int(data[:4], endianness)  # inode 번호
        self.foffset = self._make_int(data[4:8], endianness)  # 파일 오프셋
        self.fsize = self._make_int(data[8:], endianness)  # 파일 크기

    def _decode_fname(self):
        """
        파일 이름에서 실제 문자열을 추출합니다.
        """
        self.fname = self.fname[:self.fname.find('\0')]
        self.fname = self.fname.replace('\\', '/')

class PFSExtractor(binwalk.core.plugin.Plugin):
    """
    알려진 PFS/0.9 파일 시스템 포맷을 추출하기 위한 플러그인.
    """
    MODULES = ['Signature']

    def init(self):
        if self.module.extractor.enabled:
            # PFS 파일 시스템 규칙을 추가
            self.module.extractor.add_rule(regex='^pfs filesystem',
                                           extension='pfs',
                                           cmd=self.extractor)

    def _create_dir_from_fname(self, fname):
        try:
            os.makedirs(os.path.dirname(fname))  # 디렉토리를 만듦
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise e

    def extractor(self, fname):
        fname = os.path.abspath(fname)
        out_dir = binwalk.core.common.unique_file_name(os.path.join(os.path.dirname(fname), "pfs-root"))

        try:
            with PFS(fname) as fs:
                # PFS 메타 데이터의 끝은 실제 데이터의 시작 위치임
                data = binwalk.core.common.BlockFile(fname, 'rb')
                data.seek(fs.get_end_of_meta_data())
                for entry in fs.entries():
                    outfile_path = os.path.abspath(os.path.join(out_dir, entry.fname))
                    if not outfile_path.startswith(out_dir):
                        # 디렉토리 트래버설 공격 감지
                        binwalk.core.common.warning("Unpfs extractor detected directory traversal attempt for file: '%s'. Refusing to extract." % outfile_path)
                    else:
                        self._create_dir_from_fname(outfile_path)  # 디렉토리 생성
                        outfile = binwalk.core.common.BlockFile(outfile_path, 'wb')
                        outfile.write(data.read(entry.fsize))  # 파일 데이터 쓰기
                        outfile.close()
                data.close()
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            return False

        return True
