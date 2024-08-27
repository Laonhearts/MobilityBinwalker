import os
import binwalk
from nose.tools import eq_, ok_

def test_firmware_cpio():
    '''
    테스트: firmware.cpio 파일을 열고 시그니처를 스캔합니다.
    최소 하나 이상의 CPIO 시그니처가 감지되었는지 확인합니다.
    CPIO 시그니처만이 감지되었는지 확인합니다.
    '''
    
    # 테스트에 사용할 입력 벡터 파일의 경로를 설정합니다.
    input_vector_file = os.path.join(os.path.dirname(__file__),
                                     "input-vectors",
                                     "firmware.cpio")

    # Binwalk를 사용하여 시그니처를 스캔합니다.
    scan_result = binwalk.scan(input_vector_file,
                               signature=True,
                               quiet=True)

    # 사용된 모듈의 개수를 테스트합니다.
    eq_(len(scan_result), 1)

    # 스캔 결과가 있는지 확인합니다.
    ok_(len(scan_result[0].results) > 0)

    # 첫 번째 결과는 오프셋 0에 있어야 합니다.
    eq_(scan_result[0].results[0].offset, 0)

    # 감지된 것이 모두 CPIO 아카이브 항목인지 확인합니다.
    for result in scan_result[0].results:
        ok_(result.description.startswith("ASCII cpio archive"))
