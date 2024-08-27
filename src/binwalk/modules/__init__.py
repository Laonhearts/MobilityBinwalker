# capstone 모듈을 찾을 수 없는 경우 disasm 모듈을 로드하지 않음

try:

    from binwalk.modules.disasm import Disasm

except ImportError:

    pass

# lzma 모듈을 찾을 수 없는 경우 compression 모듈을 로드하지 않음
try:

    from binwalk.modules.compression import RawCompression

except ImportError:

    pass

# 기타 필수 모듈들 로드
from binwalk.modules.signature import Signature   # 시그니처 스캔 모듈
from binwalk.modules.hexdiff import HexDiff       # 이진 비교 모듈
from binwalk.modules.general import General       # 일반적인 파일 분석 모듈
from binwalk.modules.extractor import Extractor   # 데이터 추출 모듈
from binwalk.modules.entropy import Entropy       # 엔트로피 분석 모듈
