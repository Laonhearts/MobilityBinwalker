__all__ = ['scan', 'execute', 'ModuleException']

from binwalk.core.module import Modules
from binwalk.core.version import __version__  # 이 파일은 setup.py에 의해 자동으로 생성되며, .gitignore에 의해 무시됩니다.
from binwalk.core.exceptions import ModuleException

# 편의 함수들
def scan(*args, **kwargs):
    with Modules(*args, **kwargs) as m:
        objs = m.execute()
    return objs

# 'execute' 함수는 'scan' 함수를 호출하는 편의 함수로, 동일한 기능을 합니다.
def execute(*args, **kwargs):
    return scan(*args, **kwargs)
