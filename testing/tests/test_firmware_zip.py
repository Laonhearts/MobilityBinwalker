import os
import binwalk
from nose.tools import eq_, ok_

def test_firmware_zip():
    '''
    테스트: firmware.zip 파일을 열고 시그니처를 스캔합니다.
    예상되는 모든 시그니처가 감지되었는지 확인합니다.
    또한 예상되지 않은 시그니처가 감지되지 않았는지도 확인합니다.
    '''
    
    # 기대되는 결과를 [오프셋, 설명] 형식으로 리스트에 저장합니다.
    expected_results = [
	[0, 'Zip archive data, at least v1.0 to extract, name: dir655_revB_FW_203NA/'],
	[6410581, 'End of Zip archive, footer length: 22'],
    ]

    # 테스트에 사용할 입력 벡터 파일의 경로를 설정합니다.
    input_vector_file = os.path.join(os.path.dirname(__file__),
                                     "input-vectors",
                                     "firmware.zip")

    # Binwalk를 사용하여 시그니처를 스캔합니다.
    scan_result = binwalk.scan(input_vector_file,
                               signature=True,
                               quiet=True)

    # 사용된 모듈의 개수를 테스트합니다.
    eq_(len(scan_result), 1)

    # 해당 모듈에서 발견된 결과의 개수를 테스트합니다.
    eq_(len(scan_result[0].results), len(expected_results))

    # 각 결과의 오프셋과 설명이 기대하는 결과와 일치하는지 테스트합니다.
    for i in range(0, len(scan_result[0].results)):
        eq_(scan_result[0].results[i].offset, expected_results[i][0])
        eq_(scan_result[0].results[i].description, expected_results[i][1])
