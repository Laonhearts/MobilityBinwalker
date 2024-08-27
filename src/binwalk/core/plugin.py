# 플러그인을 지원하고 관리하는 핵심 코드

import os
import imp
import inspect
import binwalk.core.common
import binwalk.core.settings
from binwalk.core.compat import *
from binwalk.core.exceptions import IgnoreFileException


class Plugin(object):
    '''
    모든 플러그인 클래스의 기반이 되는 클래스입니다.
    '''
    # 이 플러그인이 로드되어야 하는 모듈 이름의 대소문자 구분 목록입니다.
    # 모듈 이름이 지정되지 않은 경우, 플러그인은 모든 모듈에 대해 로드됩니다.
    MODULES = []

    def __init__(self, module):
        '''
        클래스 생성자입니다.

        @module - 이 플러그인이 로드된 현재 모듈에 대한 핸들입니다.

        반환값 없음.
        '''
        self.module = module

        if not self.MODULES or self.module.name in self.MODULES:
            self._enabled = True
            self.init()
        else:
            self._enabled = False

    def __str__(self):
        return self.__class__.__name__

    def init(self):
        '''
        필요한 경우 자식 클래스가 이 메서드를 재정의해야 합니다.
        플러그인 초기화 시 호출됩니다.
        '''
        pass

    def pre_scan(self):
        '''
        필요한 경우 자식 클래스가 이 메서드를 재정의해야 합니다.
        '''
        pass

    def new_file(self, fp):
        '''
        필요한 경우 자식 클래스가 이 메서드를 재정의해야 합니다.
        '''
        pass

    def scan(self, module):
        '''
        필요한 경우 자식 클래스가 이 메서드를 재정의해야 합니다.
        '''
        pass

    def post_scan(self):
        '''
        필요한 경우 자식 클래스가 이 메서드를 재정의해야 합니다.
        '''
        pass


class Plugins(object):
    '''
    플러그인 콜백 함수를 로드하고 호출하는 클래스로, Binwalk.scan / Binwalk.single_scan에 의해 자동으로 처리됩니다.
    스캔 중 Binwalk.plugins 객체를 통해 이 클래스의 인스턴스에 접근할 수 있습니다.

    각 플러그인은 사용자 또는 시스템 플러그인 디렉터리에 배치되어야 하며, 'Plugin'이라는 클래스를 정의해야 합니다.
    Plugin 클래스 생성자(__init__)는 현재 Binwalk 클래스의 인스턴스를 인수로 받습니다.
    Plugin 클래스 생성자는 파일 또는 파일 세트를 스캔하기 전에 한 번 호출됩니다.
    Plugin 클래스 소멸자(__del__)는 모든 파일을 스캔한 후 한 번 호출됩니다.

    기본적으로 모든 플러그인은 binwalk 서명 스캔 중에 로드됩니다. 기본적으로 비활성화하고 싶은 플러그인은 'ENABLED'라는 클래스 변수를 생성하고 False로 설정할 수 있습니다. ENABLED가 False로 설정된 경우, 플러그인은 플러그인 허용 목록에 명시적으로 지정된 경우에만 로드됩니다.
    '''

    SCAN = 'scan'
    NEWFILE = 'new_file'
    LOADFILE = 'load_file'
    PRESCAN = 'pre_scan'
    POSTSCAN = 'post_scan'
    MODULE_EXTENSION = '.py'

    def __init__(self, parent=None):
        self.scan = []
        self.pre_scan = []
        self.new_file = []
        self.load_file = []
        self.post_scan = []
        self.parent = parent
        self.settings = binwalk.core.settings.Settings()

    def __enter__(self):
        return self

    def __exit__(self, t, v, traceback):
        pass

    def _call_plugins(self, callback_list, obj=None):
        for callback in callback_list:
            try:
                try:
                    callback()
                except TypeError:
                    if obj is not None:
                        callback(obj)
            except KeyboardInterrupt:
                raise
            except IgnoreFileException:
                raise
            except SystemError:
                raise
            except Exception as e:
                binwalk.core.common.warning(
                    "%s.%s 실패 [%s]: '%s'" % (callback.__module__, callback.__name__, type(e), e))

    def _find_plugin_class(self, plugin):
        for (name, klass) in inspect.getmembers(plugin, inspect.isclass):
            if issubclass(klass, Plugin) and klass != Plugin:
                return klass
        raise Exception("플러그인에서 Plugin 클래스를 찾지 못했습니다: " + plugin)

    def list_plugins(self):
        '''
        모든 사용자 및 시스템 플러그인 모듈의 목록을 가져옵니다.

        반환 값은 다음과 같은 딕셔너리입니다:

            {
                'user': {
                    'modules': [모듈 이름 목록],
                    'descriptions': {'module_name': '모듈 설명'},
                    'enabled': {'module_name': True},
                    'path': "모듈 플러그인 디렉터리의 경로"
                },
                'system': {
                    'modules': [모듈 이름 목록],
                    'descriptions': {'module_name': '모듈 설명'},
                    'enabled': {'module_name': True},
                    'path': "모듈 플러그인 디렉터리의 경로"
                }
            }
        '''

        plugins = {
            'user': {
                'modules': [],
                'descriptions': {},
                'enabled': {},
                'path': None,
            },
            'system': {
                'modules': [],
                'descriptions': {},
                'enabled': {},
                'path': None,
            }
        }

        for key in plugins.keys():
            if key == 'user':
                plugins[key]['path'] = self.settings.user.plugins
            else:
                plugins[key]['path'] = self.settings.system.plugins

            if plugins[key]['path']:
                for file_name in os.listdir(plugins[key]['path']):
                    if file_name.endswith(self.MODULE_EXTENSION):
                        module = file_name[:-len(self.MODULE_EXTENSION)]

                        try:
                            plugin = imp.load_source(module, os.path.join(plugins[key]['path'], file_name))
                            plugin_class = self._find_plugin_class(plugin)

                            plugins[key]['enabled'][module] = True
                            plugins[key]['modules'].append(module)
                        except KeyboardInterrupt:
                            raise
                        except TypeError:
                            pass  # 플러그인이 아닌 Python 파일은 무시합니다.
                        except Exception as e:
                            binwalk.core.common.warning(
                                "플러그인 '%s' 로드 중 오류 발생: %s" % (file_name, str(e)))
                            plugins[key]['enabled'][module] = False

                        try:
                            plugins[key]['descriptions'][module] = plugin_class.__doc__.strip().split('\n')[0]
                        except KeyboardInterrupt:
                            raise
                        except Exception:
                            plugins[key]['descriptions'][module] = '설명 없음'
        return plugins

    def load_plugins(self):
        plugins = self.list_plugins()
        self._load_plugin_modules(plugins['user'])
        self._load_plugin_modules(plugins['system'])

    def _load_plugin_modules(self, plugins):
        for module in plugins['modules']:
            try:
                file_path = os.path.join(plugins['path'], module + self.MODULE_EXTENSION)
            except KeyboardInterrupt:
                raise
            except Exception:
                continue

            try:
                plugin = imp.load_source(module, file_path)
                plugin_class = self._find_plugin_class(plugin)

                class_instance = plugin_class(self.parent)
                if not class_instance._enabled:
                    continue

                try:
                    self.scan.append(getattr(class_instance, self.SCAN))
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass

                try:
                    self.load_file.append(getattr(class_instance, self.LOADFILE))
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass

                try:
                    self.pre_scan.append(getattr(class_instance, self.PRESCAN))
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass

                try:
                    self.post_scan.append(getattr(class_instance, self.POSTSCAN))
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass

                try:
                    self.new_file.append(getattr(class_instance, self.NEWFILE))
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass

            except KeyboardInterrupt:
                raise
            except Exception as e:
                binwalk.core.common.warning("플러그인 모듈 '%s' 로드에 실패했습니다: %s" % (module, str(e)))

    def pre_scan_callbacks(self, obj):
        return self._call_plugins(self.pre_scan)

    def load_file_callbacks(self, fp):
        return self._call_plugins(self.load_file, fp)

    def new_file_callbacks(self, fp):
        return self._call_plugins(self.new_file, fp)

    def post_scan_callbacks(self, obj):
        return self._call_plugins(self.post_scan)

    def scan_callbacks(self, obj):
        return self._call_plugins(self.scan, obj)
