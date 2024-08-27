# Binwalk 모듈 및 지원 클래스와 관련된 핵심 코드입니다.
# 특히, 모든 Binwalk 모듈의 기본 클래스인 Module 클래스와
# Binwalk 모듈을 관리하고 실행하는 주 클래스인 Modules 클래스가 중요합니다.

import io
import os
import sys
import time
import inspect
import argparse
import traceback
from copy import copy
import binwalk
import binwalk.core.statuserver
import binwalk.core.common
import binwalk.core.settings
import binwalk.core.plugin
from binwalk.core.compat import *
from binwalk.core.exceptions import *

class Option(object):
    '''
    모듈이 명령 줄 옵션을 선언할 수 있도록 하는 컨테이너 클래스입니다.
    '''

    def __init__(self, kwargs={}, priority=0, description="", short="", long="", type=None, dtype=None, hidden=False):
        '''
        클래스 생성자.

        @kwargs      - 이 명령 줄 옵션에 의해 영향을 받는 kwarg 키-값 쌍의 딕셔너리입니다.
        @priority    - 0에서 100까지의 값. 우선순위가 높은 옵션은 낮은 우선순위의 옵션에 의해 설정된 kwarg 값을 재정의합니다.
        @description - 도움말 출력에 표시될 설명입니다.
        @short       - 사용할 짧은 옵션(선택적)입니다.
        @long        - 사용할 긴 옵션(없으면 이 옵션은 도움말 출력에 표시되지 않습니다).
        @type        - 허용되는 데이터 유형(io.FileIO/argparse.FileType/binwalk.core.common.BlockFile, list, str, int, float 중 하나).
        @dtype       - 도움말 출력에 표시될 허용되는 유형 문자열입니다.
        @hidden      - True로 설정되면 이 옵션은 도움말 출력에 표시되지 않습니다.

        반환 값은 없습니다.
        '''
        self.kwargs = kwargs
        self.priority = priority
        self.description = description
        self.short = short
        self.long = long
        self.type = type
        self.dtype = dtype
        self.hidden = hidden

        if not self.dtype and self.type:
            if self.type in [io.FileIO, argparse.FileType, binwalk.core.common.BlockFile]:
                self.dtype = 'file'
            elif self.type in [int, float, str]:
                self.dtype = self.type.__name__
            else:
                self.type = str
                self.dtype = str.__name__

    def convert(self, value, default_value):
        if self.type and (self.type.__name__ == self.dtype):
            # int()를 사용할 때 기본 베이스를 0으로 지정하여 베이스를 자동으로 감지합니다.
            if self.type == int:
                t = self.type(value, 0)
            else:
                t = self.type(value)
        elif default_value or default_value is False:
            t = default_value
        else:
            t = value

        return t

class Kwarg(object):
    '''
    모듈이 예상하는 __init__ kwarg(s)를 지정할 수 있도록 하는 컨테이너 클래스입니다.
    '''

    def __init__(self, name="", default=None, description=""):
        '''
        클래스 생성자.

        @name        - Kwarg 이름.
        @default     - 기본 kwarg 값.
        @description - 설명 문자열.

        반환 값은 없습니다.
        '''
        self.name = name
        self.default = default
        self.description = description

class Dependency(object):
    '''
    모듈 의존성을 선언하기 위한 컨테이너 클래스입니다.
    '''

    def __init__(self, attribute="", name="", kwargs={}):
        self.attribute = attribute
        self.name = name
        self.kwargs = kwargs
        self.module = None

class Result(object):
    '''
    스캔 결과를 저장하고 접근하기 위한 일반 클래스입니다.
    '''

    def __init__(self, **kwargs):
        '''
        클래스 생성자.

        @offset      - 결과의 파일 오프셋입니다.
        @size        - 결과의 크기(알려진 경우).
        @description - 사용자에게 표시될 결과 설명입니다.
        @module      - 결과를 생성한 모듈의 이름입니다.
        @file        - 스캔된 파일의 파일 객체입니다.
        @valid       - 결과가 유효하면 True로 설정, 그렇지 않으면 False로 설정.
        @display     - 사용자에게 결과를 표시하려면 True로 설정, 그렇지 않으면 False로 설정.
        @extract     - 이 결과를 추출 대상으로 표시하려면 True로 설정.
        @plot        - 이 결과를 엔트로피 플롯에서 제외하려면 False로 설정.
        @name        - 발견된 결과의 이름(해당하지 않거나 알 수 없는 경우 None).

        필요한 경우 추가 kwargs를 제공합니다.
        반환 값은 없습니다.
        '''
        self.offset = 0
        self.size = 0
        self.description = ''
        self.module = ''
        self.file = None
        self.valid = True
        self.display = True
        self.extract = True
        self.plot = True
        self.name = None

        for (k, v) in iterator(kwargs):
            setattr(self, k, v)

class Error(Result):
    '''
    binwalk.core.module.Result의 하위 클래스입니다.
    '''

    def __init__(self, **kwargs):
        '''
        binwalk.core.module.Result와 동일한 kwargs를 수락하지만 다음과 같은 항목도 추가됩니다:

        @exception - 예외 발생 시 예외 객체입니다.

        반환 값은 없습니다.
        '''
        self.exception = None
        Result.__init__(self, **kwargs)

class Module(object):
    '''
    모든 모듈 클래스는 이 클래스를 상속받아야 합니다.
    '''
    # 모듈 제목, 도움말 출력에 표시됩니다.
    TITLE = ""

    # binwalk.core.module.Option 명령 줄 옵션 목록
    CLI = []

    # __init__에서 수락되는 binwalk.core.module.Kwargs 목록
    KWARGS = []

    # 모든 모듈의 기본 의존성 목록입니다.
    # 이 목록을 재정의하려면 그로 인해 발생할 수 있는 결과를 충분히 이해해야 합니다.
    DEFAULT_DEPENDS = [
        Dependency(name='General', attribute='config'),
        Dependency(name='Extractor', attribute='extractor'),
    ]

    # 개별 모듈에서 필요한 경우 채울 수 있는 binwalk.core.module.Dependency 인스턴스 목록입니다.
    DEPENDS = []

    # 스캔 중에 헤더를 인쇄하기 위한 포맷 문자열입니다.
    # self.header를 호출하기 전에 설정해야 합니다.
    HEADER_FORMAT = "%-12s  %-12s    %s\n"

    # 스캔 중에 각 결과를 인쇄하기 위한 포맷 문자열입니다.
    # self.result를 호출하기 전에 설정해야 합니다.
    RESULT_FORMAT = "%-12d  0x%-12X  %s\n"

    # 자세한 헤더 출력에서 사용자 지정 정보를 인쇄하기 위한 포맷 문자열입니다.
    # self.header를 호출하기 전에 설정해야 합니다.
    VERBOSE_FORMAT = ""

    # 스캔 중에 인쇄할 헤더입니다.
    # None으로 설정하면 헤더를 인쇄하지 않습니다.
    # 이 포맷 문자열에 따라 포맷됩니다.
    # self.header를 호출하기 전에 설정해야 합니다.
    HEADER = ["DECIMAL", "HEXADECIMAL", "DESCRIPTION"]

    # 스캔 중에 인쇄할 Result 속성 이름입니다.
    # None으로 설정하면 결과를 인쇄하지 않습니다.
    # 이 포맷 문자열에 따라 포맷됩니다.
    # self.result를 호출하기 전에 설정해야 합니다.
    RESULT = ["offset", "offset", "description"]

    # 자세한 헤더 출력에서 인쇄할 사용자 지정 데이터입니다.
    # 이 포맷 문자열에 따라 포맷됩니다.
    # self.header를 호출하기 전에 설정해야 합니다.
    VERBOSE = []

    # True로 설정하면 파일 및 오프셋 속성이 있는 결과마다 진행 상태가 자동으로 업데이트됩니다.
    AUTO_UPDATE_STATUS = True

    # 우선 순위가 높은 모듈은 먼저 실행됩니다.
    PRIORITY = 5

    # 우선 순위가 높은 모듈은 도움말 출력에서 먼저 표시됩니다.
    ORDER = 5

    # 주 모듈이 아닌 경우 False로 설정합니다 (예: General, Extractor 모듈).
    PRIMARY = True

    def __init__(self, parent, **kwargs):
        self.errors = []
        self.results = []

        self.parent = parent
        self.target_file_list = []
        self.status = None
        self.enabled = False
        self.previous_next_file_fp = None
        self.current_target_file_name = None
        self.name = self.__class__.__name__
        self.plugins = binwalk.core.plugin.Plugins(self)
        self.dependencies = self.DEFAULT_DEPENDS + self.DEPENDS

        process_kwargs(self, kwargs)

        self.plugins.load_plugins()

        try:
            self.load()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.error(exception=e)

        try:
            self.target_file_list = list(self.config.target_files)
        except AttributeError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, x, z, y):
        return None

    def load(self):
        '''
        모듈이 로드될 때 호출됩니다.
        모듈 하위 클래스에서 재정의할 수 있습니다.
        '''
        return None

    def unload(self):
        '''
        모듈이 로드될 때 호출됩니다.
        모듈 하위 클래스에서 재정의할 수 있습니다.
        '''
        return None

    def reset(self):
        '''
        새로운 주 모듈이 시작되기 직전에 의존성 모듈에 대해서만 호출됩니다.
        '''
        return None

    def init(self):
        '''
        self.run이 호출되기 전에 호출됩니다.
        모듈 하위 클래스에서 재정의할 수 있습니다.

        반환 값은 없습니다.
        '''
        return None

    def run(self):
        '''
        메인 모듈 루틴을 실행합니다.
        모듈 하위 클래스에서 재정의해야 합니다.

        성공 시 True를 반환하고 실패 시 False를 반환합니다.
        '''
        return False

    def callback(self, r):
        '''
        모든 모듈의 결과를 처리합니다. 유효한 결과가 발견되면 모든 의존성 모듈에 대해 호출됩니다.

        @r - 결과, binwalk.core.module.Result의 인스턴스.

        반환 값은 없습니다.
        '''
        return None

    def validate(self, r):
        '''
        결과를 검증합니다.
        모듈 하위 클래스에서 재정의할 수 있습니다.

        @r - 결과, binwalk.core.module.Result의 인스턴스.

        반환 값은 없습니다.
        '''
        r.valid = True
        return None

    def _plugins_pre_scan(self):
        self.plugins.pre_scan_callbacks(self)

    def _plugins_load_file(self, fp):
        try:
            self.plugins.load_file_callbacks(fp)
            return True
        except IgnoreFileException:
            return False

    def _plugins_new_file(self, fp):
        self.plugins.new_file_callbacks(fp)

    def _plugins_post_scan(self):
        self.plugins.post_scan_callbacks(self)

    def _plugins_result(self, r):
        self.plugins.scan_callbacks(r)

    def _build_display_args(self, r):
        args = []

        if self.RESULT:
            result = self.RESULT if isinstance(self.RESULT, list) else [self.RESULT]

            for name in result:
                value = getattr(r, name)

                # 표시되는 오프셋은 기본 주소로 오프셋 되어야 합니다.
                if name == 'offset':
                    value += self.config.base

                args.append(value)

        return args

    def _unload_dependencies(self):
        # 모든 의존성 모듈에 대해 unload 메서드를 호출합니다.
        # 이 모듈들은 실행 후 바로 언로드될 수 없으며, 의존하는 모듈이 완료될 때까지 유지되어야 합니다.
        # 따라서, 이는 Modules.run 'unload' 호출과 별도로 수행되어야 합니다.
        for dependency in self.dependencies:
            try:
                getattr(self, dependency.attribute).unload()
            except AttributeError:
                continue

    def next_file(self, close_previous=True):
        '''
        스캔할 다음 파일을 가져옵니다(적용 가능한 경우 추출된 파일 포함).
        또한 self.status를 재초기화합니다.
        모든 모듈은 이 메서드를 통해 대상 파일 목록에 접근해야 합니다.
        '''
        fp = None

        # 파일이 닫혀 있는지 확인하여 IOError(너무 많은 파일 열림)를 방지합니다.
        if close_previous:
            try:
                self.previous_next_file_fp.close()
            except KeyboardInterrupt:
                raise
            except Exception:
                pass

        # 대기 중인 추출된 파일을 target_files 목록에 추가하고 추출기의 대기 파일 목록을 재설정합니다.
        self.target_file_list += self.extractor.pending

        # 다른 파일을 계속 처리하기 전에 모든 의존성을 재설정합니다.
        # 특히 추출 모듈의 경우, 각 파일에 대해 기본 출력 디렉토리 경로와 대기 파일 목록을 재설정해야 하므로 중요합니다.
        self.reset_dependencies()

        while self.target_file_list:
            next_target_file = self.target_file_list.pop(0)

            # self.target_file_list의 값은 이미 열려 있는 파일(BlockFile 인스턴스) 또는 스캔을 위해 열어야 하는 파일 경로입니다.
            if isinstance(next_target_file, (str, unicode)):
                fp = self.config.open_file(next_target_file)
            else:
                fp = next_target_file

            if not fp:
                break
            else:
                if not self.config.file_name_filter(fp) or not self._plugins_load_file(fp):
                    fp.close()
                    fp = None
                    continue
                else:
                    self.status.clear()
                    self.status.total = fp.length
                    break

        if fp is not None:
            self.current_target_file_name = fp.path
            self.status.fp = fp
        else:
            self.current_target_file_name = None
            self.status.fp = None

        self.previous_next_file_fp = fp

        self._plugins_new_file(fp)

        return fp

    def clear(self, results=True, errors=True):
        '''
        결과와 오류 목록을 초기화합니다.
        '''
        if results:
            self.results = []
        if errors:
            self.errors = []

    def result(self, r=None, **kwargs):
        '''
        결과를 검증하고 self.results에 저장하며 출력합니다.
        binwalk.core.module.Result 클래스와 동일한 kwargs를 수락합니다.

        @r - 기존의 binwalk.core.module.Result 인스턴스.

        반환 값은 binwalk.core.module.Result의 인스턴스입니다.
        '''
        if r is None:
            r = Result(**kwargs)

        # 현재 모듈의 이름을 결과에 추가합니다.
        r.module = self.__class__.__name__

        # 유효한 결과를 보고하는 모든 모듈은 enabled로 표시되어야 합니다.
        if not self.enabled:
            self.enabled = True
        self.validate(r)
        self._plugins_result(r)

        # 결과가 수동으로 업데이트되지 않으면 자동으로 진행 상태를 업데이트합니다.
        if r.offset and r.file and self.AUTO_UPDATE_STATUS:
            self.status.total = r.file.length
            self.status.completed = r.offset
            self.status.fp = r.file

        for dependency in self.dependencies:
            try:
                getattr(self, dependency.attribute).callback(r)
            except AttributeError:
                continue

        if r.valid:
            self.results.append(r)

            if r.display:
                display_args = self._build_display_args(r)
                if display_args:
                    self.config.display.format_strings(self.HEADER_FORMAT, self.RESULT_FORMAT)
                    self.config.display.result(*display_args)

        return r

    def error(self, **kwargs):
        '''
        self.errors에 지정된 오류를 저장합니다.

        binwalk.core.module.Error 클래스와 동일한 kwargs를 수락합니다.

        반환 값은 없습니다.
        '''
        exception_header_width = 100

        e = Error(**kwargs)
        e.module = self.__class__.__name__

        self.errors.append(e)

        if e.exception:
            sys.stderr.write("\n" + e.module + " Exception: " + str(e.exception) + "\n")
            sys.stderr.write("-" * exception_header_width + "\n")
            traceback.print_exc(file=sys.stderr)
            sys.stderr.write("-" * exception_header_width + "\n\n")
        elif e.description:
            sys.stderr.write("\n" + e.module + " Error: " + e.description + "\n\n")

    def header(self):
        '''
        self.HEADER 및 self.HEADER_FORMAT에 정의된 스캔 헤더를 표시합니다.

        반환 값은 없습니다.
        '''
        self.config.display.format_strings(self.HEADER_FORMAT, self.RESULT_FORMAT)
        self.config.display.add_custom_header(self.VERBOSE_FORMAT, self.VERBOSE)

        if isinstance(self.HEADER, list):
            self.config.display.header(*self.HEADER, file_name=self.current_target_file_name)
        elif self.HEADER:
            self.config.display.header(self.HEADER, file_name=self.current_target_file_name)

    def footer(self):
        '''
        스캔 푸터를 표시합니다.

        반환 값은 없습니다.
        '''
        self.config.display.footer()

    def reset_dependencies(self):
        # 모든 의존성 모듈을 재설정합니다.
        for dependency in self.dependencies:
            if hasattr(self, dependency.attribute):
                getattr(self, dependency.attribute).reset()

    def main(self):
        '''
        self.init을 호출하고 self.config.display를 초기화하며 self.run을 호출합니다.

        self.run에서 반환된 값을 반환합니다.
        '''
        self.status = self.parent.status
        self.modules = self.parent.executed_modules

        # 추출기 모듈에 대한 특별 예외 처리로, --matryoshka가 지정된 경우
        # 상세 설정을 재정의할 수 있도록 합니다.
        if hasattr(self, "extractor") and self.extractor.config.verbose:
            self.config.verbose = self.config.display.verbose = True

        if not self.config.files:
            binwalk.core.common.debug("대상 파일이 지정되지 않았습니다. 모듈 %s가 종료되었습니다." % self.name)
            return False

        self.reset_dependencies()

        try:
            self.init()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.error(exception=e)
            return False

        try:
            self.config.display.format_strings(self.HEADER_FORMAT, self.RESULT_FORMAT)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.error(exception=e)
            return False

        self._plugins_pre_scan()

        try:
            retval = self.run()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.error(exception=e)
            return False

        self._plugins_post_scan()

        return retval

class Status(object):
    '''
    모듈 상태를 추적하는 클래스(예: 완료 %).
    '''

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.clear()

    def clear(self):
        for (k, v) in iterator(self.kwargs):
            setattr(self, k, v)

class Modules(object):
    '''
    모듈 실행 및 관리에 사용되는 주요 클래스입니다.
    '''

    def __init__(self, *argv, **kargv):
        '''
        클래스 생성자.

        @argv  - 명령 줄 옵션의 리스트입니다. 프로그램 이름은 포함하지 않아야 합니다(예: sys.argv[1:]).
        @kargv - 명령 줄 옵션의 키워드 딕셔너리입니다.

        반환 값은 없습니다.
        '''
        self.arguments = []
        self.executed_modules = {}
        self.default_dependency_modules = {}
        self.status = Status(completed=0, total=0, fp=None, running=False, shutdown=False, finished=False)
        self.status_server_started = False
        self.status_service = None

        self._set_arguments(list(argv), kargv)

    def cleanup(self):
        if self.status_service:
            self.status_service.server.socket.shutdown(1)
            self.status_service.server.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, t, v, b):
        self.cleanup()

    def _set_arguments(self, argv=None, kargv=None):
        if kargv:
            for (k, v) in iterator(kargv):
                    k = self._parse_api_opt(k)
                    if v is not True and v is not False and v is not None:
                        if not isinstance(v, list):
                            v = [v]
                        for value in v:
                            if not isinstance(value, str):
                                value = str(bytes2str(value))
                            argv.append(k)
                            argv.append(value)
                    else:
                        # 값이 True일 때만 추가합니다. 이는 함수 호출로 값을 토글할 수 있도록 합니다.
                        if v:
                            argv.append(k)

        if not argv and not self.arguments:
            self.arguments = sys.argv[1:]
        elif argv:
            self.arguments = argv

    def _parse_api_opt(self, opt):
        # 인수가 이미 하이픈으로 시작하면 앞에 하이픈을 추가하지 않습니다.
        if opt.startswith('-'):
            return opt
        # 짧은 옵션은 1자입니다.
        elif len(opt) == 1:
            return '-' + opt
        else:
            return '--' + opt

    def list(self, attribute="run"):
        '''
        지정된 속성을 가진 모든 모듈을 찾습니다.

        @attribute - 원하는 모듈 속성입니다.

        지정된 속성을 포함하는 모듈 목록을 반환합니다.
        '''
        import binwalk.modules
        modules = {}

        for (name, module) in inspect.getmembers(binwalk.modules):
            if inspect.isclass(module) and hasattr(module, attribute):
                modules[module] = module.PRIORITY

        # 사용자 정의 모듈
        import imp
        user_modules = binwalk.core.settings.Settings().user.modules
        for file_name in os.listdir(user_modules):
            if not file_name.endswith('.py'):
                continue
            module_name = file_name[:-3]
            try:
                user_module = imp.load_source(module_name, os.path.join(user_modules, file_name))
            except KeyboardInterrupt:
                raise
            except Exception as e:
                binwalk.core.common.warning("모듈 '%s' 로드 중 오류 발생: %s" % (file_name, str(e)))

            for (name, module) in inspect.getmembers(user_module):
                if inspect.isclass(module) and hasattr(module, attribute):
                    modules[module] = module.PRIORITY

        return sorted(modules, key=modules.get, reverse=True)

    def help(self):
        '''
        형식화된 도움말 출력을 생성합니다.

        도움말 문자열을 반환합니다.
        '''
        modules = {}
        help_string = "\n"
        help_string += "Binwalk v%s\n" % binwalk.__version__
        help_string += "Craig Heffner, ReFirmLabs\n"
        help_string += "https://github.com/ReFirmLabs/binwalk\n"
        help_string += "\n"
        help_string += "사용법: binwalk [옵션] [파일1] [파일2] [파일3] ...\n"

        # 모듈과 해당 ORDER 속성의 사전을 빌드합니다.
        # 이를 통해 ORDER 속성으로 모듈을 정렬하여 표시하기 쉽게 만듭니다.
        for module in self.list(attribute="CLI"):
            if module.CLI:
                modules[module] = module.ORDER

        for module in sorted(modules, key=modules.get, reverse=True):
            help_string += "\n%s 옵션:\n" % module.TITLE

            for module_option in module.CLI:
                if module_option.long and not module_option.hidden:
                    long_opt = '--' + module_option.long

                    if module_option.dtype:
                        optargs = "=<%s>" % module_option.dtype
                    else:
                        optargs = ""

                    if module_option.short:
                        short_opt = "-" + module_option.short + ","
                    else:
                        short_opt = "   "

                    fmt = "    %%s %%s%%-%ds%%s\n" % (25 - len(long_opt))
                    help_string += fmt % (short_opt, long_opt, optargs, module_option.description)

        return help_string + "\n"

    def execute(self, *args, **kwargs):
        '''
        args/kwargs에 지정된 옵션에 따라 적절한 모듈을 모두 실행합니다.

        실행된 모듈 객체 목록을 반환합니다.
        '''
        run_modules = []
        orig_arguments = self.arguments

        if args or kwargs:
            self._set_arguments(list(args), kwargs)

        # 모든 모듈 실행
        for module in self.list():
            obj = self.run(module)

        # enabled로 표시된 모든 모듈을 run_modules 목록에 추가합니다.
        for (module, obj) in iterator(self.executed_modules):
            # 모듈이 활성화되었으며 기본 모듈이거나 결과/오류를 보고한 경우
            if obj.enabled and (obj.PRIMARY or obj.results or obj.errors):
                run_modules.append(obj)

        self.arguments = orig_arguments

        return run_modules

    def run(self, module, dependency=False, kwargs={}):
        '''
        특정 모듈을 실행합니다.
        '''
        try:
            obj = self.load(module, kwargs)

            if isinstance(obj, binwalk.core.module.Module) and obj.enabled:
                obj.main()
                self.status.clear()

            # 모듈이 의존성으로 로드되지 않은 경우, 실행된 모듈 사전에 추가합니다.
            if not dependency:
                self.executed_modules[module] = obj

                # unload 메서드는 모듈이 완료되었음을 알리고,
                # 필요한 정리 작업을 수행할 기회를 제공합니다.
                obj._unload_dependencies()
                obj.unload()
        except KeyboardInterrupt:
            # 상태 서버에 종료를 지시하고 정리할 시간을 줍니다.
            if self.status.running:
                self.status.shutdown = True
                while not self.status.finished:
                    time.sleep(0.1)
            raise

        return obj

    def load(self, module, kwargs={}):
        argv = self.argv(module, argv=self.arguments)
        argv.update(kwargs)
        argv.update(self.dependencies(module, argv['enabled']))
        return module(self, **argv)

    def dependencies(self, module, module_enabled):
        import binwalk.modules
        attributes = {}

        for dependency in module.DEFAULT_DEPENDS + module.DEPENDS:

            # 의존 모듈은 binwalk.modules.__init__.py에 의해 가져와야 합니다.
            if hasattr(binwalk.modules, dependency.name):
                dependency.module = getattr(binwalk.modules, dependency.name)
            else:
                raise ModuleException("%s는 %s에 의존합니다. 그러나 binwalk.modules.__init__.py에서 찾을 수 없습니다.\n" % (str(module), dependency.name))

            # 재귀적 의존성은 허용되지 않습니다.
            if dependency.module == module:
                continue

            # 모듈이 활성화되었거나 사용자 정의 kwargs가 없는 경우에만 의존성을 로드합니다. 그렇지 않으면 오류가 발생합니다.
            if module_enabled or not dependency.kwargs:
                depobj = self.run(dependency.module, dependency=True, kwargs=dependency.kwargs)

            # 의존성 로드에 실패하면, 복구 불가능한 오류로 간주하고 예외를 발생시킵니다.
            if depobj.errors:
                raise ModuleException(dependency.name + " 모듈 로드에 실패했습니다.")
            else:
                attributes[dependency.attribute] = depobj

        return attributes

    def argv(self, module, argv=sys.argv[1:]):
        '''
        지정된 모듈에 특정한 argv 옵션을 처리합니다.

        @module - argv를 처리할 모듈입니다.
        @argv   - 명령 줄 인수 목록입니다(argv[0]을 제외한).

        지정된 모듈에 대한 kwargs 딕셔너리를 반환합니다.
        '''
        kwargs = {'enabled': False}
        last_priority = {}
        parser = argparse.ArgumentParser(add_help=False)
        parser.short_to_long = {}

        for m in self.list(attribute="CLI"):
            for module_option in m.CLI:
                parser_args = []
                parser_kwargs = {}

                if not module_option.long:
                    continue

                if module_option.short:
                    parser_args.append('-' + module_option.short)
                parser_args.append('--' + module_option.long)
                parser_kwargs['dest'] = module_option.long

                if module_option.type is None:
                    parser_kwargs['action'] = 'store_true'
                elif module_option.type == list:
                    parser_kwargs['action'] = 'append'
                    parser.short_to_long[module_option.short] = module_option.long

                parser.add_argument(*parser_args, **parser_kwargs)

        args, unknown = parser.parse_known_args(argv)
        args = args.__dict__

        for module_option in module.CLI:
            if module_option.type == binwalk.core.common.BlockFile:
                for k in get_keys(module_option.kwargs):
                    kwargs[k] = []
                    for unk in unknown:
                        kwargs[k].append(unk)
            elif has_key(args, module_option.long) and args[module_option.long] not in [None, False]:
                for (name, default_value) in iterator(module_option.kwargs):
                    if not has_key(last_priority, name) or last_priority[name] <= module_option.priority:
                        last_priority[name] = module_option.priority
                        try:
                            kwargs[name] = module_option.convert(args[module_option.long], default_value)
                        except Exception as e:
                            raise ModuleException("잘못된 사용법: %s" % str(e))

        binwalk.core.common.debug("%s :: %s => %s" % (module.TITLE, str(argv), str(kwargs)))
        return kwargs

    def kwargs(self, obj, kwargs):
        '''
        모듈의 kwargs를 처리합니다. 모든 모듈은 이 메서드를 사용하여 kwarg 처리를 해야 합니다.

        @obj    - 모듈의 인스턴스(예: self)
        @kwargs - 모듈에 전달된 kwargs

        반환 값은 없습니다.
        '''
        if hasattr(obj, "KWARGS"):
            for module_argument in obj.KWARGS:
                arg_value = kwargs.get(module_argument.name, copy(module_argument.default))
                setattr(obj, module_argument.name, arg_value)

            for (k, v) in iterator(kwargs):
                if not hasattr(obj, k):
                    setattr(obj, k, v)
        else:
            raise Exception("binwalk.core.module.Modules.process_kwargs: %s에는 'KWARGS' 속성이 없습니다." % str(obj))

    def status_server(self, port):
        '''
        지정된 포트에서 진행 상태 표시기 TCP 서비스를 시작합니다.
        이 서비스는 인스턴스당 한 번만 시작되며, 이 메서드가 여러 번 호출되더라도 한 번만 실행됩니다.

        상태 서비스를 시작하지 못한 경우, 비치명적 오류로 간주되며,
        사용자에게 경고 메시지가 표시되지만 정상적인 작동은 계속됩니다.
        '''
        if not self.status_server_started:
            self.status_server_started = True
            try:
                self.status_service = binwalk.core.statuserver.StatusServer(port, self)
            except Exception as e:
                binwalk.core.common.warning("포트 %d에서 상태 서버를 시작하지 못했습니다: %s" % (port, str(e)))

def process_kwargs(obj, kwargs):
    '''
    binwalk.core.module.Modules.kwargs의 편의 래퍼입니다.

    @obj    - 클래스 객체(binwalk.core.module.Module의 하위 클래스 인스턴스).
    @kwargs - 객체의 __init__ 메서드에 제공된 kwargs.

    반환 값은 없습니다.
    '''
    with Modules() as m:
        kwargs = m.kwargs(obj, kwargs)
    return kwargs

def show_help(fd=sys.stdout):
    '''
    binwalk.core.module.Modules.help의 편의 래퍼입니다.

    @fd - write 메서드를 가진 객체(예: sys.stdout, sys.stderr 등).

    반환 값은 없습니다.
    '''
    with Modules() as m:
        fd.write(m.help())
