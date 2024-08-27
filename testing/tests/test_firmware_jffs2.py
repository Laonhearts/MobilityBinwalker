import os
import binwalk
from nose.tools import eq_, ok_

def test_firmware_jffs2():
    '''
    테스트: firmware.jffs2 파일을 열고 시그니처를 스캔합니다.
    JFFS2 시그니처만이 감지되었는지 확인합니다.
    처음 감지된 시그니처만 표시되었는지 확인합니다.
    '''
    
    # 테스트에 사용할 입력 벡터 파일의 경로를 설정합니다.
    input_vector_file = os.path.join(os.path.dirname(__file__),
                                     "input-vectors",
                                     "firmware.jffs2")

    # Binwalk를 사용하여 시그니처를 스캔합니다.
    scan_result = binwalk.scan(input_vector_file,
                               signature=True,
                               quiet=True)

    # 사용된 모듈의 개수를 테스트합니다.
    eq_(len(scan_result), 1)

    # 해당 모듈에서 여러 개의 결과가 나왔는지 확인합니다.
    ok_(len(scan_result[0].results) > 1)

    # 첫 번째 결과를 저장합니다.
    first_result = scan_result[0].results[0]

    # 첫 번째 결과의 오프셋이 0인지 확인합니다.
    eq_(first_result.offset, 0)

    # 첫 번째 결과가 JFFS2 파일 시스템인지 확인합니다.
    ok_(first_result.description.startswith("JFFS2 filesystem"))

    # 첫 번째 결과가 표시되었는지 확인합니다.
    ok_(first_result.display == True)

    # 모든 결과가 JFFS2 파일 시스템인지 확인하고, 첫 번째를 제외한 나머지가 표시되지 않았는지 확인합니다.
    for result in scan_result[0].results[1:]:
        ok_(result.description.startswith("JFFS2 filesystem"))
        ok_(result.display == False)
