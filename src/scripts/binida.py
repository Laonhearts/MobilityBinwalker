if idaapi.IDA_SDK_VERSION <= 695:
    import idc
    import idaapi
    import binwalk
if idaapi.IDA_SDK_VERSION >= 700:
    import ida_idc
    import ida_idaapi
    import binwalk

    from idaapi import *
else:
    pass

# 'try'를 사용하여 이전 API와의 호환성을 유지
# 핸들러를 위한 Actions API 사용
try:
    class OpHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)  # 부모 클래스 초기화

        def activate(self, ctx):
            # opcode_scan을 실행하여 IDB 파일에서 명령어(opcode)를 검색
            arg = None
            a = binwalk_t()
            a.opcode_scan(arg)
            return 1

        def update(self, ctx):
            # 메뉴 항목을 항상 활성화된 상태로 유지
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass

# 'try'를 사용하여 이전 API와의 호환성을 유지
# 핸들러를 위한 Actions API 사용
try:
    class SigHandler(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)  # 부모 클래스 초기화

        def activate(self, ctx):
            # signature_scan을 실행하여 IDB 파일에서 파일 서명을 검색
            arg = None
            b = binwalk_t()
            b.signature_scan(arg)
            return 1

        def update(self, ctx):
            # 메뉴 항목을 항상 활성화된 상태로 유지
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass

# IDA 플러그인을 정의하는 클래스
class binwalk_t(idaapi.plugin_t):
    flags = 0  # 플러그인 플래그
    comment = "Scan the current IDB for file signatures"  # 플러그인 설명
    help = ""  # 도움말 텍스트 (없음)
    wanted_name = "Binwalk IDA Plugin"  # 플러그인 이름
    wanted_hotkey = ""  # 핫키 (없음)

    def init(self):
        # IDA SDK 버전이 695 이하인 경우 메뉴 항목을 추가
        if idaapi.IDA_SDK_VERSION <= 695:
            self.menu_context_1 = idaapi.add_menu_item(
                "Search/", "binwalk opcodes", "", 0, self.opcode_scan, (None,))
            self.menu_context_2 = idaapi.add_menu_item(
                "Search/", "binwalk signatures", "", 0, self.signature_scan, (None,))

        # IDA SDK 버전이 700 이상인 경우, Actions API를 사용하여 메뉴 항목을 추가
        if idaapi.IDA_SDK_VERSION >= 700:
            # opcode 스캔 메뉴 항목을 추가
            action_desc = idaapi.action_desc_t(
                'my:opaction',  # 액션 이름 (고유 ID)
                'Binwalk opcodes',  # 액션에 대한 텍스트
                OpHandler(),  # 액션 핸들러
                '',  # 선택적 단축키
                'Binwalk opcodes',  # 선택적 툴팁
                )

            # 액션 등록
            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu(
                'Search/',
                'my:opaction',
                idaapi.SETMENU_APP)

            # signature 스캔 메뉴 항목을 추가
            action_desc = idaapi.action_desc_t(
                'my:sigaction',
                'Binwalk signatures',
                SigHandler(),
                '',
                'Binwalk signatures',
                )

            # 액션 등록
            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu(
                'Search/',
                'my:sigaction',
                idaapi.SETMENU_APP)

        else:
            pass

        return idaapi.PLUGIN_KEEP  # 플러그인을 유지

    def term(self):
        # IDA SDK 버전이 695 이하인 경우 메뉴 항목을 삭제
        if idaapi.IDA_SDK_VERSION <= 695:
            idaapi.del_menu_item(self.menu_context_1)
            idaapi.del_menu_item(self.menu_context_2)
        # IDA SDK 버전이 700 이상인 경우 액션을 메뉴에서 분리
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(
                'Search/',
                'my:opaction')
            idaapi.detach_action_from_menu(
                'Search/',
                'my:sigaction')
        else:
            pass

        return None

    def run(self, arg):
        return None

    # IDB 파일에서 서명을 스캔하는 메서드
    def signature_scan(self, arg):
        binwalk.scan(idc.GetIdbPath(), signature=True)

    # IDB 파일에서 명령어(opcode)를 스캔하는 메서드
    def opcode_scan(self, arg):
        binwalk.scan(idc.GetIdbPath(), opcode=True)

# IDA 플러그인의 진입점을 정의
def PLUGIN_ENTRY():
    return binwalk_t()
