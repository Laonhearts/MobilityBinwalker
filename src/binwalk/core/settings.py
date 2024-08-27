# Binwalk 설정(추출 규칙, 서명 파일 등)을 로드하고 접근하는 코드입니다.

import os
import binwalk.core.common as common
from binwalk.core.compat import *


class Settings(object):

    '''
    Binwalk 설정 클래스입니다. 사용자 및 시스템 파일 경로와 일반 구성 설정에 접근하는 데 사용됩니다.

    클래스 인스턴스를 생성한 후에는 self.paths 딕셔너리를 통해 파일 경로에 접근할 수 있습니다.
    시스템 파일 경로는 'system' 키 아래에, 사용자 파일 경로는 'user' 키 아래에 나열됩니다.

    'user' 및 'system' 키 아래에 유효한 파일 이름은 다음과 같습니다:

        o BINWALK_MAGIC_FILE  - 기본 binwalk 매직 파일의 경로.
        o PLUGINS             - 플러그인 디렉토리의 경로.
    '''
    # 서브 디렉토리들
    BINWALK_USER_DIR = "binwalk"
    BINWALK_MAGIC_DIR = "magic"
    BINWALK_CONFIG_DIR = "config"
    BINWALK_MODULES_DIR = "modules"
    BINWALK_PLUGINS_DIR = "plugins"

    # 파일 이름들
    PLUGINS = "plugins"
    EXTRACT_FILE = "extract.conf"
    BINARCH_MAGIC_FILE = "binarch"

    def __init__(self):
        '''
        클래스 생성자입니다. 파일 경로를 열거하고 self.paths를 채웁니다.
        '''
        # 사용자 binwalk 디렉토리의 경로
        self.user_dir = self._get_user_config_dir()
        # 시스템 전역 binwalk 디렉토리의 경로
        self.system_dir = common.get_module_path()

        # 모든 사용자별 파일의 경로를 빌드합니다.
        self.user = common.GenericContainer(
            binarch=self._user_path(self.BINWALK_MAGIC_DIR, self.BINARCH_MAGIC_FILE),
            magic=self._magic_signature_files(user_only=True),
            extract=self._user_path(self.BINWALK_CONFIG_DIR, self.EXTRACT_FILE),
            modules=self._user_path(self.BINWALK_MODULES_DIR),
            plugins=self._user_path(self.BINWALK_PLUGINS_DIR))

        # 모든 시스템 전역 파일의 경로를 빌드합니다.
        self.system = common.GenericContainer(
            binarch=self._system_path(self.BINWALK_MAGIC_DIR, self.BINARCH_MAGIC_FILE),
            magic=self._magic_signature_files(system_only=True),
            extract=self._system_path(self.BINWALK_CONFIG_DIR, self.EXTRACT_FILE),
            plugins=self._system_path(self.BINWALK_PLUGINS_DIR))

    def _magic_signature_files(self, system_only=False, user_only=False):
        '''
        사용자/시스템 매직 서명 파일을 찾습니다.

        @system_only - True로 설정된 경우, 시스템 매직 파일 디렉토리만 검색됩니다.
        @user_only   - True로 설정된 경우, 사용자 매직 파일 디렉토리만 검색됩니다.

        사용자/시스템 매직 서명 파일 목록을 반환합니다.
        '''
        files = []
        user_binarch = self._user_path(self.BINWALK_MAGIC_DIR, self.BINARCH_MAGIC_FILE)
        system_binarch = self._system_path(self.BINWALK_MAGIC_DIR, self.BINARCH_MAGIC_FILE)

        def list_files(dir_path):
            # 숨김 파일은 무시합니다.
            return [os.path.join(dir_path, x) for x in os.listdir(dir_path) if not x.startswith('.')]

        if not system_only:
            user_dir = os.path.join(self.user_dir, self.BINWALK_USER_DIR, self.BINWALK_MAGIC_DIR)
            files += list_files(user_dir)
        if not user_only:
            system_dir = os.path.join(self.system_dir, self.BINWALK_MAGIC_DIR)
            files += list_files(system_dir)

        # 기본 서명 파일 목록에서 binarch 서명을 포함하지 않습니다.
        # 이 서명은 명령줄에서 -A가 지정된 경우에만 로드됩니다.
        if user_binarch in files:
            files.remove(user_binarch)
        if system_binarch in files:
            files.remove(system_binarch)

        return files

    def find_magic_file(self, fname, system_only=False, user_only=False):
        '''
        시스템 / 사용자 매직 파일 디렉토리에서 지정된 매직 파일 이름을 찾습니다.

        @fname       - 매직 파일의 이름.
        @system_only - True로 설정된 경우, 시스템 매직 파일 디렉토리만 검색됩니다.
        @user_only   - True로 설정된 경우, 사용자 매직 파일 디렉토리만 검색됩니다.

        system_only 및 user_only가 설정되지 않은 경우, 항상 사용자 디렉토리가 먼저 검색됩니다.

        성공 시 파일 경로를 반환합니다. 실패 시 None을 반환합니다.
        '''
        loc = None

        if not system_only:
            fpath = self._user_path(self.BINWALK_MAGIC_DIR, fname)
            if os.path.exists(fpath) and common.file_size(fpath) > 0:
                loc = fpath

        if loc is None and not user_only:
            fpath = self._system_path(self.BINWALK_MAGIC_DIR, fname)
            if os.path.exists(fpath) and common.file_size(fpath) > 0:
                loc = fpath

        return fpath

    def _get_user_config_dir(self):
        '''
        사용자 설정 디렉토리의 경로를 가져옵니다.
        '''
        try:
            xdg_path = os.getenv('XDG_CONFIG_HOME')
            if xdg_path is not None:
                return xdg_path
        except Exception:
            pass

        return os.path.join(self._get_user_dir(), '.config')

    def _get_user_dir(self):
        '''
        사용자의 홈 디렉토리를 가져옵니다.
        '''
        try:
            # 이 방법은 Windows와 Unix 환경 모두에서 작동해야 합니다.
            for envname in ['USERPROFILE', 'HOME']:
                user_dir = os.getenv(envname)
                if user_dir is not None:
                    return user_dir
            if os.path.expanduser("~") is not None:
                return os.path.expanduser("~")
        except KeyboardInterrupt as e:
            raise e
        except Exception:
            pass

        return ''

    def _file_path(self, dirname, filename):
        '''
        절대 경로를 빌드하고 디렉토리 및 파일이 존재하지 않는 경우 생성합니다.

        @dirname  - 디렉토리 경로.
        @filename - 파일 이름.

        'dirname/filename'의 전체 경로를 반환합니다.
        '''
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except KeyboardInterrupt as e:
                raise e
            except Exception:
                pass

        fpath = os.path.join(dirname, filename)

        if not os.path.exists(fpath):
            try:
                open(fpath, "w").close()
            except KeyboardInterrupt as e:
                raise e
            except Exception:
                pass

        return fpath

    def _user_path(self, subdir, basename=''):
        '''
        사용자 binwalk 디렉토리의 'subdir/basename' 파일에 대한 전체 경로를 가져옵니다.

        @subdir   - 사용자 binwalk 디렉토리 내부의 서브 디렉토리.
        @basename - 서브 디렉토리 내부의 파일 이름.

        'subdir/basename' 파일의 전체 경로를 반환합니다.
        '''
        try:
            return self._file_path(os.path.join(self.user_dir, self.BINWALK_USER_DIR, subdir), basename)
        except KeyboardInterrupt as e:
            raise e
        except Exception:
            return None

    def _system_path(self, subdir, basename=''):
        '''
        시스템 binwalk 디렉토리의 'subdir/basename' 파일에 대한 전체 경로를 가져옵니다.

        @subdir   - 시스템 binwalk 디렉토리 내부의 서브 디렉토리.
        @basename - 서브 디렉토리 내부의 파일 이름.

        'subdir/basename' 파일의 전체 경로를 반환합니다.
        '''
        try:
            return self._file_path(os.path.join(self.system_dir, subdir), basename)
        except KeyboardInterrupt as e:
            raise e
        except Exception:
            return None
