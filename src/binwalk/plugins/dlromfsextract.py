import os
import zlib
import struct
import binwalk.core.plugin
import binwalk.core.common
try:
    import lzma
except ImportError as e:
    pass


class RomFSCommon(object):
    '''
    RomFS 파일 시스템에서 공통적으로 사용되는 함수들을 정의한 클래스입니다.
    '''

    def _read_next_word(self):
        # 데이터에서 다음 4바이트(32비트)를 읽어들여 정수로 변환합니다.
        value = struct.unpack("%sL" % self.endianness, self.data[self.index:self.index + 4])[0]
        self.index += 4
        return value

    def _read_next_uid(self):
        # 다음 4바이트를 읽어 UID로 변환합니다.
        uid = int(self.data[self.index:self.index + 4])
        self.index += 4
        return uid

    def _read_next_block(self, size):
        # 지정된 크기만큼 데이터를 읽어옵니다.
        size = int(size)
        data = self.data[self.index:self.index + size]
        self.index += size
        return data

    def _read_next_string(self):
        # NULL 문자 ('\x00')로 끝나는 문자열을 읽어옵니다.
        data = ""
        while True:
            byte = self.data[self.index]
            try:
                byte = chr(byte)
            except TypeError as e:
                pass

            if byte == "\x00":
                break
            else:
                data += byte
                self.index += 1
        return data


class RomFSEntry(RomFSCommon):
    '''
    RomFS 파일 시스템의 엔트리를 나타내는 클래스입니다.
    '''
    DIR_STRUCT_MASK = 0x00000001
    DATA_MASK = 0x00000008
    COMPRESSED_MASK = 0x005B0000

    def __init__(self, data, endianness="<"):
        # 클래스 초기화 시, 주어진 데이터를 파싱하여 엔트리 정보를 저장합니다.
        self.data = data
        self.endianness = endianness
        self.index = 0

        # 엔트리의 필드 값을 순서대로 읽어들입니다.
        self.type = self._read_next_word()
        self.unknown2 = self._read_next_word()
        self.unknown3 = self._read_next_word()
        self.size = self._read_next_word()
        self.unknown4 = self._read_next_word()
        self.offset = self._read_next_word()
        self.unknown5 = self._read_next_word()
        self.uid = self._read_next_uid()


class RomFSDirStruct(RomFSCommon):
    '''
    RomFS 디렉토리 구조를 나타내는 클래스입니다.
    '''
    SIZE = 0x20

    def __init__(self, data, endianness="<"):
        self.index = 0
        self.data = data
        self.endianness = endianness
        self.directory = False
        self.uid = None
        self.ls = []

        # 디렉토리 내의 모든 항목을 읽어들입니다.
        for (uid, entry) in self.next():
            if self.uid is None:
                self.uid = uid

            if entry in ['.', '..']:
                # '.' 및 '..' 항목은 디렉토리로 처리합니다.
                self.directory = True
                continue

            self.ls.append((uid, entry))

    def next(self):
        # 다음 디렉토리 항목을 반환하는 제너레이터 함수입니다.
        while self.index < len(self.data):
            uid = self._read_next_word()
            dont_care = self._read_next_word()
            entry = self._read_next_string()

            total_size = int(4 + 4 + len(entry))
            count = int(total_size / self.SIZE)
            if count == 0:
                mod = self.SIZE - total_size
            else:
                mod = self.SIZE - int(total_size - (count * self.SIZE))

            if mod > 0:
                remainder = self._read_next_block(mod)

            yield (uid, entry)


class FileContainer(object):
    '''
    RomFS 파일 시스템의 파일 엔트리를 나타내는 빈 컨테이너 클래스입니다.
    '''
    def __init__(self):
        pass


class RomFS(object):
    '''
    RomFS 파일 시스템을 처리하는 클래스입니다.
    '''
    SUPERBLOCK_SIZE = 0x20
    FILE_ENTRY_SIZE = 0x20

    def __init__(self, fname, endianness="<"):
        # RomFS 파일을 읽어들여 엔트리들을 처리합니다.
        self.endianness = endianness
        self.data = open(fname, "rb").read()
        self.entries = self._process_all_entries()

    def get_data(self, uid):
        # 주어진 UID에 해당하는 데이터를 반환합니다.
        start = self.entries[uid].offset
        end = start + self.entries[uid].size

        data = self.data[start:end]

        # 데이터를 LZMA 또는 zlib로 디컴프레션합니다.
        try:
            data = lzma.decompress(data)
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            try:
                data = zlib.decompress(data)
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                pass

        return data

    def build_path(self, uid):
        # 주어진 UID에 해당하는 파일 경로를 구축합니다.
        path = self.entries[uid].name

        while uid != 0:
            uid = self.entries[uid].parent
            path = os.path.join(self.entries[uid].name, path)

        return path.replace("..", "")

    def _process_all_entries(self):
        # RomFS 파일의 모든 엔트리를 처리하여 사전으로 반환합니다.
        entries = {}
        offset = self.SUPERBLOCK_SIZE

        while True:
            try:
                entry = RomFSEntry(self.data[offset:offset + self.FILE_ENTRY_SIZE], endianness=self.endianness)
            except ValueError as e:
                break

            if not entry.uid in entries:
                entries[entry.uid] = FileContainer()

            entries[entry.uid].offset = entry.offset
            entries[entry.uid].size = entry.size
            entries[entry.uid].type = entry.type
            if entry.uid == 0:
                entries[entry.uid].name = os.path.sep

            if entry.type & entry.DIR_STRUCT_MASK:
                # 디렉토리 엔트리인 경우, 하위 항목을 처리합니다.
                entries[entry.uid].type = "directory"
                ds = RomFSDirStruct(self.data[entry.offset:entry.offset + entry.size], endianness=self.endianness)
                for (uid, name) in ds.ls:
                    if not uid in entries:
                        entries[uid] = FileContainer()
                    entries[uid].parent = ds.uid
                    entries[uid].name = name
            else:
                # 데이터 엔트리인 경우, 파일로 처리합니다.
                entries[entry.uid].type = "data"

            offset += self.FILE_ENTRY_SIZE

        return entries


if __name__ == '__main__':
    import sys

    try:
        infile = sys.argv[1]
        outdir = sys.argv[2]
    except IndexError as e:
        print ("Usage: %s <input file> <output directory>" % sys.argv[0])
        sys.exit(1)


class DlinkROMFSExtractPlugin(binwalk.core.plugin.Plugin):
    '''
    D-Link ROMFS 파일 시스템 추출을 위한 플러그인입니다.
    '''
    MODULES = ['Signature']
    BLOCK_SIZE = 10 * 1024

    def init(self):
        # 모듈의 추출기가 활성화된 경우, D-Link ROMFS 파일 시스템에 대한
        # 추출 규칙을 등록합니다.
        if self.module.extractor.enabled:
            self.module.extractor.add_rule(
                txtrule=None,
                regex="^d-link romfs filesystem",
                extension="romfs",
                recurse=False,
                cmd=self.extractor
            )

    def extractor(self, fname):
        # D-Link ROMFS 파일 시스템을 추출하는 함수입니다.
        infile = os.path.abspath(fname)
        outdir = os.path.join(os.path.dirname(infile), "romfs-root")
        outdir = binwalk.core.common.unique_file_name(outdir)

        # TODO: 빅 엔디안 타겟 지원
        fs = RomFS(infile)
        os.mkdir(outdir)

        for (uid, info) in fs.entries.items():
            if hasattr(info, 'name') and hasattr(info, 'parent'):
                path = fs.build_path(uid).strip(os.path.sep)
                fname = os.path.join(outdir, path)

                if info.type == "directory" and not os.path.exists(fname):
                    os.makedirs(fname)
                else:
                    fdata = fs.get_data(uid)
                    with open(fname, 'wb') as fp:
                        fp.write(fdata)

        return True
