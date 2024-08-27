try:
    # Python 3.8 이상에서는 importlib.metadata를 사용하여 패키지 버전을 가져올 수 있습니다.
    from importlib import metadata
    # binwalk 패키지의 버전을 가져오는 람다 함수 정의
    get_version = lambda : metadata.version("binwalk")
except ImportError:
    try:
        # Python 3.8 이전 버전에서는 importlib_metadata 패키지를 사용해야 합니다.
        import importlib_metadata as metadata
        # binwalk 패키지의 버전을 가져오는 람다 함수 정의
        get_version = lambda: metadata.version("binwalk")
    except ImportError:
        # 위의 두 가지 방법이 실패할 경우, pkg_resources를 사용하여 패키지 버전을 가져옵니다.
        import pkg_resources
        # binwalk 패키지의 버전을 가져오는 람다 함수 정의
        get_version = lambda : pkg_resources.get_distribution("binwalk").version

# binwalk 패키지의 버전을 가져오는 함수 실행
__version__ = get_version()
