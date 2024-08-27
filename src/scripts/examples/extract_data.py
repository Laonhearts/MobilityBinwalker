#!/usr/bin/env python

import sys
import binwalk

# 추출 및 로그 기록
for module in binwalk.scan(*sys.argv[1:], signature=True, quiet=True, extract=True):
    print ("%s 결과:" % module.name)
    for result in module.results:
        if module.extractor.output.has_key(result.file.path):
            if module.extractor.output[result.file.path].extracted.has_key(result.offset):
                print ("'%s'에서 오프셋 0x%X에 '%s'를 추출하여 '%s'로 저장했습니다." % (result.file.path,
                                                                                  result.offset,
                                                                                  result.description.split(',')[0],
                                                                                  str(module.extractor.output[result.file.path].extracted[result.offset])))
