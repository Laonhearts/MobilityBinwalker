class ParserException(Exception):

    '''
    시그니처 파일 파싱 오류와 관련된 예외입니다.
    특정한 파싱 오류 상황에서 이 예외가 발생합니다.
    '''
    pass


class ModuleException(Exception):

    '''
    모듈 예외 클래스.
    이름 외에는 특별한 기능이 없습니다.
    모듈과 관련된 오류를 처리할 때 사용됩니다.
    '''
    pass


class IgnoreFileException(Exception):

    '''
    load_file 플러그인 메서드에서 사용되는 특별한 예외 클래스입니다.
    로드하려는 파일을 무시해야 하는 경우 이 예외가 발생합니다.
    '''
    pass
