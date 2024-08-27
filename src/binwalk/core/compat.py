# 모든 Python 2/3 호환성 관련 내용은 여기에 있습니다.

from __future__ import print_function
import sys
import string

# Python의 주 버전을 확인합니다.
PY_MAJOR_VERSION = sys.version_info[0]

# Python 3에서는 string.letters가 string.ascii_letters로 대체되었습니다.
if PY_MAJOR_VERSION > 2:
    string.letters = string.ascii_letters

def get_class_name_from_method(method):
    # 주어진 메서드에서 클래스 이름을 반환합니다. Python 2와 3의 차이를 처리합니다.
    if PY_MAJOR_VERSION > 2:
        return method.__self__.__class__.__name__
    else:
        return method.im_class.__name__

def iterator(dictionary):
    '''
    Python 2와 Python 3의 딕셔너리 호환성을 위한 함수.
    '''
    if PY_MAJOR_VERSION > 2:
        return dictionary.items()  # Python 3에서는 items()를 사용합니다.
    else:
        return dictionary.iteritems()  # Python 2에서는 iteritems()를 사용합니다.

def has_key(dictionary, key):
    '''
    Python 2와 Python 3의 딕셔너리 호환성을 위한 함수.
    '''
    if PY_MAJOR_VERSION > 2:
        return key in dictionary  # Python 3에서는 'in' 연산자를 사용합니다.
    else:
        return dictionary.has_key(key)  # Python 2에서는 has_key() 메서드를 사용합니다.

def get_keys(dictionary):
    '''
    Python 2와 Python 3의 딕셔너리 호환성을 위한 함수.
    '''
    if PY_MAJOR_VERSION > 2:
        return list(dictionary.keys())  # Python 3에서는 keys()가 뷰 객체를 반환하므로 리스트로 변환합니다.
    else:
        return dictionary.keys()  # Python 2에서는 keys()가 리스트를 반환합니다.

def str2bytes(string):
    '''
    Python 2와 Python 3의 문자열 호환성을 위한 함수.
    '''
    if isinstance(string, type('')) and PY_MAJOR_VERSION > 2:
        return bytes(string, 'latin1')  # Python 3에서는 문자열을 바이트로 변환합니다.
    else:
        return string  # Python 2에서는 문자열을 그대로 반환합니다.

def bytes2str(bs):
    '''
    Python 2와 Python 3의 문자열 호환성을 위한 함수.
    '''
    if isinstance(bs, type(b'')) and PY_MAJOR_VERSION > 2:
        return bs.decode('latin1')  # Python 3에서는 바이트를 문자열로 변환합니다.
    else:
        return bs  # Python 2에서는 바이트를 그대로 반환합니다.

def string_decode(string):
    '''
    Python 2와 Python 3의 문자열 디코딩 호환성을 위한 함수.
    '''
    if PY_MAJOR_VERSION > 2:
        return bytes(string, 'utf-8').decode('unicode_escape')  # Python 3에서는 유니코드 이스케이프를 디코딩합니다.
    else:
        return string.decode('string_escape')  # Python 2에서는 string_escape로 디코딩합니다.

def user_input(prompt=''):
    '''
    Python 2와 3에서 사용자 입력을 받기 위한 함수.
    '''
    return input(prompt)  # Python 2에서는 raw_input을 사용했지만, Python 3에서는 input을 사용합니다.
