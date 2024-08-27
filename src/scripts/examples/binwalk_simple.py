#!/usr/bin/env python

import binwalk

# 옵션이 지정되지 않았기 때문에, 기본적으로 sys.argv에서 옵션을 가져옵니다.
# 사실상, 이 코드는 기본 binwalk 스크립트의 기능을 복제합니다.
binwalk.scan()
