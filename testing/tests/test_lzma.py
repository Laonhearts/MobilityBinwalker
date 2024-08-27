import os
import binwalk
from nose.tools import eq_, ok_

def test_lzma():
    '''
    테스트: foobar.lzma 파일을 열고 시그니처를 스캔합니다.
    단 하나의 LZMA 시그니처가 감지되었는지 확인합니다.
    '''
    # 예상되는 결과를 문자열로 설정합니다.
    expected_result = "LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: -1 bytes"

    # 테스트에 사용할 입력 벡터 파일의 경로를 설정합니다.
    input_vector_file = os.path.join(os.path.dirname(__file__),
                                     "input-vectors",
                                     "foobar.lzma")

    # Binwalk를 사용하여 시그니처를 스캔합니다.
    scan_result = binwalk.scan(input_vector_file,
                               signature=True,  # 시그니처 검사를 수행합니다.
                               quiet=True)      # 출력 소음을 줄이기 위해 조용히 스캔합니다.

    # 사용된 모듈의 개수를 테스트합니다. 
    eq_(len(scan_result), 1)

    # 결과는 하나만 있어야 합니다.
    eq_(len(scan_result[0].results), 1)

    # 그 결과는 오프셋 0에 있어야 합니다.
    eq_(scan_result[0].results[0].offset, 0)

    # 그 결과는 LZMA 파일이어야 합니다.
    ok_(scan_result[0].results[0].description == expected_result)
