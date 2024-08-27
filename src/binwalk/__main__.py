import os
import sys

# 커스텀 프리픽스 디렉토리에 설치된 경우, binwalk가 기본 모듈 검색 경로에 없을 수 있습니다.
# 프리픽스 모듈 경로를 찾아서 sys.path의 첫 번째 항목으로 추가하려고 시도합니다.
# 'src/binwalk'가 비어 있는 문자열 대신 '.'이 되도록 보장합니다.
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _module_path in [
    # 리포지토리에서: src/scripts/ -> src/로 이동
    _parent_dir,
    # 빌드 디렉토리에서: build/scripts-3.4/ -> build/lib/로 이동
    os.path.join(_parent_dir, "lib"),
    # 기본 경로가 아닌 위치에 설치된 경우: bin/ -> lib/python3.4/site-packages/로 이동
    os.path.join(_parent_dir,
                 "lib",
                 "python%d.%d" % (sys.version_info[0], sys.version_info[1]),
                 "site-packages")
]:
    if os.path.exists(_module_path) and _module_path not in sys.path:
        sys.path = [_module_path] + sys.path

import binwalk
import binwalk.modules

def runme():
    with binwalk.Modules() as modules:
        try:
            if len(sys.argv) == 1:
                # 명령줄 인수가 제공되지 않은 경우, 도움말 메시지를 출력하고 종료합니다.
                sys.stderr.write(modules.help())
                sys.exit(1)
            # 명시적으로 활성화된 모듈이 없을 경우, 기본 서명 스캔을 명시적으로 활성화한 상태로 다시 실행합니다.
            elif not modules.execute():
                # Signature 모듈이 로드되어 있는지 확인한 후, 암시적 서명 스캔을 시도합니다.
                # 그렇지 않으면 사용자에게 제공되는 오류 메시지가 이해하기 어려울 수 있습니다.
                if hasattr(binwalk.modules, "Signature"):
                    modules.execute(*sys.argv[1:], signature=True)
                else:
                    sys.stderr.write("오류: 서명 스캔이 지원되지 않습니다; ")
                    sys.stderr.write("python-lzma를 설치하고 다시 시도해보세요.\n")
                    sys.exit(2)
        except binwalk.ModuleException as e:
            sys.exit(3)

def main():
    try:
        # 코드를 프로파일링하는 특수 옵션입니다. 디버그 용도로만 사용됩니다.
        if '--profile' in sys.argv:
            import cProfile
            sys.argv.pop(sys.argv.index('--profile'))
            cProfile.run('runme()')
        else:
            runme()
    except IOError:
        pass
    except KeyboardInterrupt:
        sys.stdout.write("\n")

if __name__ == "__main__":
    main()
