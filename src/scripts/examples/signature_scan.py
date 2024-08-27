#!/usr/bin/env python

import sys
import binwalk

try:
    # 명령줄에서 지정된 파일에 대해 시그니처 스캔을 수행하고,
    # 일반적인 binwalk 출력을 억제합니다.
    for module in binwalk.scan(*sys.argv[1:], signature=True, quiet=True):
        print ("%s 결과:" % module.name)

        for result in module.results:
            print ("\t%s    0x%.8X    %s [%s]" % (result.file.name,
                                                  result.offset,
                                                  result.description,
                                                  str(result.valid)))
except binwalk.ModuleException as e:
    pass
