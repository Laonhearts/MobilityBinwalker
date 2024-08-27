# TCP 소켓 서비스를 통해 스캔 상태 정보를 제공합니다.
# 현재는 서명 스캔에만 작동합니다.

import time
import errno
import threading
import binwalk.core.compat

# Python 2/3 호환성
try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer


class StatusRequestHandler(SocketServer.BaseRequestHandler):
    '''
    클라이언트 요청을 처리하는 클래스입니다.
    클라이언트에 스캔 상태 정보를 제공하며, 스캔이 완료되었는지 여부를 확인합니다.
    '''

    def handle(self):
        message_format = "%s     %3d%%     [ %d / %d ]"  # 상태 메시지 형식
        last_status_message_len = 0  # 이전 상태 메시지 길이
        status_message = ''  # 상태 메시지
        message_sent = False  # 메시지 전송 여부

        self.server.binwalk.status.running = True  # 스캔이 실행 중임을 표시

        while True:
            time.sleep(0.1)

            try:
                # 이전 상태 메시지를 지우기 위한 처리
                self.request.send(binwalk.core.compat.str2bytes('\b' * last_status_message_len))
                self.request.send(binwalk.core.compat.str2bytes(' ' * last_status_message_len))
                self.request.send(binwalk.core.compat.str2bytes('\b' * last_status_message_len))

                # 서버가 종료 요청을 받았는지 확인
                if self.server.binwalk.status.shutdown:
                    self.server.binwalk.status.finished = True  # 스캔이 완료됨을 표시
                    break

                # 총 스캔된 바이트가 0이 아닌 경우 상태 메시지를 생성
                if self.server.binwalk.status.total != 0:
                    percentage = ((float(self.server.binwalk.status.completed) / float(self.server.binwalk.status.total)) * 100)
                    status_message = message_format % (
                        self.server.binwalk.status.fp.path,
                        percentage,
                        self.server.binwalk.status.completed,
                        self.server.binwalk.status.total
                    )
                # 초기 메시지를 아직 전송하지 않은 경우
                elif not message_sent:
                    status_message = "No status information available at this time!"  # 초기 메시지 설정
                else:
                    continue

                # 상태 메시지 길이 저장
                last_status_message_len = len(status_message)
                # 상태 메시지를 클라이언트로 전송
                self.request.send(binwalk.core.compat.str2bytes(status_message))
                message_sent = True  # 메시지가 전송되었음을 표시
            except IOError as e:
                # 클라이언트가 연결을 끊은 경우
                if e.errno == errno.EPIPE:
                    break
            except Exception as e:
                binwalk.core.common.debug('StatusRequestHandler exception: ' + str(e) + '\n')
            except KeyboardInterrupt as e:
                raise e

        self.server.binwalk.status.running = False  # 스캔이 더 이상 실행 중이 아님을 표시
        return


class ThreadedStatusServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    '''
    다중 스레드로 작동하는 상태 서버 클래스입니다.
    클라이언트의 동시 요청을 처리할 수 있습니다.
    '''
    daemon_threads = True  # 데몬 스레드로 설정하여 서버가 강제 종료될 수 있도록 함
    allow_reuse_address = True  # 주소 재사용 허용


class StatusServer(object):
    '''
    상태 서버를 초기화하고 실행하는 클래스입니다.
    '''

    def __init__(self, port, binwalk):
        '''
        초기화 메서드입니다. 상태 서버를 생성하고 백그라운드에서 실행합니다.

        @port - 상태 서버가 실행될 포트 번호.
        @binwalk - binwalk 객체, 스캔 상태를 추적합니다.
        '''
        self.server = ThreadedStatusServer(('127.0.0.1', port), StatusRequestHandler)  # 상태 서버 생성
        self.server.binwalk = binwalk  # binwalk 객체 연결

        t = threading.Thread(target=self.server.serve_forever)  # 서버를 백그라운드에서 실행할 스레드 생성
        t.setDaemon(True)  # 스레드를 데몬으로 설정하여 메인 프로그램 종료 시 함께 종료되도록 함
        t.start()  # 스레드 실행
