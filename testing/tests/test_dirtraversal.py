import os
import binwalk
from nose.tools import eq_, ok_, assert_equal, assert_not_equal

def test_dirtraversal():
    '''
    테스트: dirtraversal.tar 파일을 열어 시그니처를 스캔합니다.
    위험한 심볼릭 링크가 정상적으로 처리되었는지 확인합니다.
    '''
    # 악성 심볼릭 링크 목록: 이 파일들은 비정상적으로 처리되어야 합니다.
    bad_symlink_file_list = ['foo', 'bar', 'subdir/foo2', 'subdir/bar2']
    # 정상 심볼릭 링크 목록: 이 파일들은 정상적으로 유지되어야 합니다.
    good_symlink_file_list = ['subdir/README_link', 'README2_link']

    # 테스트에 사용할 입력 벡터 파일의 경로를 설정합니다.
    input_vector_file = os.path.join(os.path.dirname(__file__),
                                     "input-vectors",
                                     "dirtraversal.tar")

    # 추출된 파일들이 저장될 출력 디렉토리의 경로를 설정합니다.
    output_directory = os.path.join(os.path.dirname(__file__),
                                    "input-vectors",
                                    "_dirtraversal.tar.extracted")

    # Binwalk를 사용하여 시그니처를 스캔하고 파일을 추출합니다.
    scan_result = binwalk.scan(input_vector_file,
                               signature=True,
                               extract=True,
                               quiet=True)[0]

    # 악성 심볼릭 링크가 비정상적으로 처리되었는지 확인합니다.
    for symlink in bad_symlink_file_list:
        linktarget = os.path.realpath(os.path.join(output_directory, symlink))
        assert_equal(linktarget, os.devnull)  # 악성 링크는 /dev/null로 리다이렉트 되어야 합니다.

    # 정상적인 심볼릭 링크가 정상적으로 유지되었는지 확인합니다.
    for symlink in good_symlink_file_list:
        linktarget = os.path.realpath(os.path.join(output_directory, symlink))
        assert_not_equal(linktarget, os.devnull)  # 정상 링크는 원래 위치로 리다이렉트 되어야 합니다.
