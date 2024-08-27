#!/usr/bin/env python
# 주어진 입력 벡터 파일에 대한 Binwalk 시그니처 테스트 스크립트를 자동으로 생성합니다.
# 생성된 테스트 스크립트는 tests 디렉토리에 작성되며, 
# 입력 벡터 파일은 tests/input-vectors/ 디렉토리에 위치해야 합니다.

import os
import sys
import binwalk

# 테스트 스크립트의 템플릿
test_script_template = """
import os
import binwalk
from nose.tools import eq_, ok_

def test_%s():
    '''
    Test: Open %s, scan for signatures
    verify that all (and only) expected signatures are detected
    '''
    expected_results = [
%s
    ]

    input_vector_file = os.path.join(os.path.dirname(__file__),
                                     "input-vectors",
                                     "%s")

    scan_result = binwalk.scan(input_vector_file,
                               signature=True,
                               quiet=True)

    # Test number of modules used
    eq_(len(scan_result), 1)

    # Test number of results for that module
    eq_(len(scan_result[0].results), len(expected_results))

    # Test result-description
    for i in range(0, len(scan_result[0].results)):
        eq_(scan_result[0].results[i].offset, expected_results[i][0])
        eq_(scan_result[0].results[i].description, expected_results[i][1])
"""

# 입력 벡터 파일의 경로를 명령줄 인자로부터 가져옴
try:
    target_file = sys.argv[1]
except IndexError:
    sys.stderr.write("Usage: %s <input vector file>\n" % sys.argv[0])
    sys.exit(1)

# 파일 이름에서 확장자와 특수 문자를 제거하여 함수 이름으로 사용
target_file_basename = os.path.basename(target_file)
scan_function_name = target_file_basename.replace('.', '_').replace('-', '_')
expected_results = ""

# Binwalk을 사용하여 입력 파일에서 시그니처를 스캔
signature = binwalk.scan(target_file, signature=True, term=True)[0]

# 스캔 결과를 기반으로 예상 결과 리스트 생성
for result in signature.results:
    expected_results += "\t[%d, '%s'],\n" % (result.offset, result.description)

# 템플릿에 데이터를 채워 최종 테스트 스크립트 생성
test_script = test_script_template % (scan_function_name,
                                      target_file_basename,
                                      expected_results,
                                      target_file_basename)

# 생성된 테스트 스크립트를 tests 디렉토리에 저장
test_script_path = os.path.join("tests", "test_%s.py" % scan_function_name)

with open(test_script_path, "w") as fp:
    fp.write(test_script)

# 완료 메시지를 출력하고 종료
sys.stdout.write("Generated test script for '%s' and saved it to '%s'\n" % (target_file, test_script_path))
sys.exit(0)
