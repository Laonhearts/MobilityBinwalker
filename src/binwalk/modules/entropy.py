# 입력 파일들의 엔트로피를 계산하고, 선택적으로 그래프로 출력하는 모듈입니다.

import os
import sys
import math
import zlib
import binwalk.core.common
from binwalk.core.compat import *
from binwalk.core.module import Module, Option, Kwarg

try:

    from numba import njit  # numba를 사용하여 JIT 컴파일을 통한 성능 향상

except ImportError:

    def njit(func):
    
        return func  # numba가 없을 경우 JIT을 사용하지 않고 함수를 그대로 반환

class Entropy(Module):

    # 엔트로피 분석을 수행하는 클래스

    XLABEL = 'Offset'
    YLABEL = 'Entropy'

    XUNITS = 'B'
    YUNITS = 'E'

    FILE_WIDTH = 1024
    FILE_FORMAT = 'png'

    COLORS = ['g', 'r', 'c', 'm', 'y']  # 그래프에 사용될 색상 목록

    DEFAULT_BLOCK_SIZE = 1024  # 기본 블록 크기
    DEFAULT_DATA_POINTS = 2048  # 기본 데이터 포인트 수

    DEFAULT_TRIGGER_HIGH = .95  # 상승 엣지 트리거 임계값
    DEFAULT_TRIGGER_LOW = .85  # 하강 엣지 트리거 임계값

    TITLE = "Entropy"  # 모듈의 제목
    ORDER = 8  # 모듈 실행 순서

    # 명령줄 인터페이스 옵션 설정
    CLI = [
        Option(short='E',
               long='entropy',
               kwargs={'enabled': True},
               description='파일의 엔트로피를 계산'),
        Option(short='F',
               long='fast',
               kwargs={'use_zlib': True},
               description='빠르지만 덜 상세한 엔트로피 분석 사용'),
        Option(short='J',
               long='save',
               kwargs={'save_plot': True},
               description='그래프를 PNG로 저장'),
        Option(short='Q',
               long='nlegend',
               kwargs={'show_legend': False},
               description='엔트로피 플롯 그래프에서 범례 생략'),
        Option(short='N',
               long='nplot',
               kwargs={'do_plot': False},
               description='엔트로피 플롯 그래프를 생성하지 않음'),
        Option(short='H',
               long='high',
               type=float,
               kwargs={'trigger_high': DEFAULT_TRIGGER_HIGH},
               description='상승 엣지 엔트로피 트리거 임계값 설정 (기본값: %.2f)' % DEFAULT_TRIGGER_HIGH),
        Option(short='L',
               long='low',
               type=float,
               kwargs={'trigger_low': DEFAULT_TRIGGER_LOW},
               description='하강 엣지 엔트로피 트리거 임계값 설정 (기본값: %.2f)' % DEFAULT_TRIGGER_LOW),
    ]

    KWARGS = [
        Kwarg(name='enabled', default=False),
        Kwarg(name='save_plot', default=False),
        Kwarg(name='trigger_high', default=DEFAULT_TRIGGER_HIGH),
        Kwarg(name='trigger_low', default=DEFAULT_TRIGGER_LOW),
        Kwarg(name='use_zlib', default=False),
        Kwarg(name='display_results', default=True),
        Kwarg(name='do_plot', default=True),
        Kwarg(name='show_legend', default=True),
        Kwarg(name='block_size', default=0),
    ]

    # 이 모듈을 마지막에 실행하여 다른 모듈의 결과를 처리하고 엔트로피 그래프에 오버레이합니다.
    PRIORITY = 0

    def init(self):     # 모듈 초기화 함수
        
        self.HEADER[-1] = "ENTROPY"
        self.max_description_length = 0
        self.file_markers = {}
        self.output_file = None

        # 엔트로피 분석에 사용할 알고리즘 설정
        if self.use_zlib:
        
            self.algorithm = self.gzip
        
        else:
        
            if 'numpy' in sys.modules:
        
                self.algorithm = self.shannon_numpy
        
            else:
        
                self.algorithm = self.shannon

        # 다른 모듈들의 결과를 가져와 엔트로피 그래프에 표시할 마커 설정
        for (module, obj) in iterator(self.modules):
        
            for result in obj.results:
        
                if result.plot and result.file and result.description:
        
                    description = result.description.split(',')[0]

                    if not has_key(self.file_markers, result.file.name):
        
                        self.file_markers[result.file.name] = []

                    if len(description) > self.max_description_length:
        
                        self.max_description_length = len(description)

                    self.file_markers[result.file.name].append((result.offset, description))

        # 다른 모듈이 실행되었고 결과를 생성한 경우, 엔트로피 결과를 터미널에 표시하지 않음
        if self.file_markers:
        
            self.display_results = False

        # 블록 크기가 설정되지 않은 경우 기본 값으로 설정
        if not self.block_size:
        
            if self.config.block:
        
                self.block_size = self.config.block
        
            else:
        
                self.block_size = None

    def _entropy_sigterm_handler(self, *args):
        
        print("모든 작업을 포기합니다.")

    def run(self):  # 모듈 실행 함수
        
        self._run()

    def _run(self):     # 메인 실행 함수

        if self.do_plot:
    
            try:
    
                if self.save_plot:
    
                    import matplotlib as mpl
    
                    mpl.use('Agg')  # X 서버가 없는 시스템에서 그래프를 저장할 수 있도록 설정
    
                import matplotlib.pyplot as plt
    
            except ImportError:
    
                binwalk.core.common.warning("matplotlib 모듈을 가져오는 데 실패하여 시각적 엔트로피 그래프 생성이 비활성화됩니다.")
    
                self.do_plot = False

        for fp in iter(self.next_file, None):
    
            if self.display_results:
    
                self.header()

            self.calculate_file_entropy(fp)

            if self.display_results:
    
                self.footer()

    def calculate_file_entropy(self, fp):   # 파일의 엔트로피를 계산하는 함수
    
        last_edge = None  # 마지막으로 표시된 상승/하강 엣지
        trigger_reset = True  # 트리거 리셋 플래그

        self.clear(results=True)  # 이전 분석 결과 제거

        # 블록 크기 설정
        if self.block_size is None:
    
            block_size = fp.size / self.DEFAULT_DATA_POINTS
            block_size = int(block_size + ((self.DEFAULT_BLOCK_SIZE - block_size) % self.DEFAULT_BLOCK_SIZE))
    
        else:
    
            block_size = self.block_size

        if block_size <= 0:
    
            block_size = self.DEFAULT_BLOCK_SIZE

        binwalk.core.common.debug("엔트로피 블록 크기 (%d 데이터 포인트): %d" %
                                  (self.DEFAULT_DATA_POINTS, block_size))

        while True:

            file_offset = fp.tell()

            (data, dlen) = fp.read_block()
            
            if dlen < 1:
            
                break

            i = 0
            
            while i < dlen:
            
                entropy = self.algorithm(data[i:i + block_size])
                display = self.display_results
                description = "%f" % entropy

                if not self.config.verbose:
            
                    if last_edge in [None, 0] and entropy > self.trigger_low:
            
                        trigger_reset = True
            
                    elif last_edge in [None, 1] and entropy < self.trigger_high:
            
                        trigger_reset = True

                    if trigger_reset and entropy >= self.trigger_high:
            
                        description = "상승 엔트로피 엣지 (%f)" % entropy
            
                        display = self.display_results
            
                        last_edge = 1
            
                        trigger_reset = False
            
                    elif trigger_reset and entropy <= self.trigger_low:
            
                        description = "하강 엔트로피 엣지 (%f)" % entropy
            
                        display = self.display_results
            
                        last_edge = 0
            
                        trigger_reset = False
            
                    else:
            
                        display = False
                        description = "%f" % entropy

                r = self.result(offset=(file_offset + i),
                                file=fp,
                                entropy=entropy,
                                description=description,
                                display=display)

                i += block_size

        if self.do_plot:
           
            self.plot_entropy(fp.name)

    def shannon(self, data):    # Shannon 엔트로피 분석을 수행하는 함수.
        
        entropy = 0

        if data:

            length = len(data)

            seen = dict(((chr(x), 0) for x in range(0, 256)))
            
            for byte in data:
            
                seen[byte] += 1

            for x in range(0, 256):
            
                p_x = float(seen[chr(x)]) / length
            
                if p_x > 0:
            
                    entropy -= p_x * math.log(p_x, 2)

        return (entropy / 8)

    def shannon_numpy(self, data):
        
        if data:
        
            return self._shannon_numpy(bytes2str(data))
        
        else:
        
            return 0
    
    @staticmethod
    
    @njit
    
    def _shannon_numpy(data):   # Numpy를 사용하여 Shannon 엔트로피를 계산하는 함수

        A = np.frombuffer(data, dtype=np.uint8)
    
        pA = np.bincount(A) / len(A)
    
        entropy = -np.nansum(pA*np.log2(pA))
    
        return (entropy / 8)

    def gzip(self, data, truncate=True):    # zlib 압축 비율을 기반으로 엔트로피 분석을 수행하는 함수. , 이는 Shannon 엔트로피 분석보다 빠르지만 정확도는 떨어집니다.
        
        e = float(float(len(zlib.compress(str2bytes(data), 9))) / float(len(data)))

        if truncate and e > 1.0:

            e = 1.0

        return e

    def plot_entropy(self, fname):  # 엔트로피를 그래프로 표시하는 함수
        
        try:
        
            import matplotlib.pyplot as plt
        
        except ImportError:
        
            return

        i = 0
        x = []
        y = []
        
        plotted_colors = {}

        for r in self.results:
        
            x.append(r.offset)
            y.append(r.entropy)

        fig = plt.figure()

        try:
        
            ax = fig.add_subplot(1, 1, 1, autoscale_on=True, facecolor='black')
        
        except AttributeError:
        
            ax = fig.add_subplot(1, 1, 1, autoscale_on=True, axisbg='black')

        ax.set_title(self.TITLE)
        ax.set_xlabel(self.XLABEL)
        ax.set_ylabel(self.YLABEL)
        ax.plot(x, y, 'y', lw=2)

        ax.plot(-(max(x)*.001), 1.1, lw=0)
        ax.plot(-(max(x)*.001), 0, lw=0)

        if self.show_legend and has_key(self.file_markers, fname):
        
            for (offset, description) in self.file_markers[fname]:
        
                if has_key(plotted_colors, description):
        
                    color = plotted_colors[description]
        
                    description = None
        
                else:
        
                    color = self.COLORS[i]
        
                    plotted_colors[description] = color

                    i += 1
        
                    if i >= len(self.COLORS):
        
                        i = 0

                ax.plot([offset, offset], [0, 1.1], '%s-' % color, lw=2, label=description)

            ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))

        if self.save_plot:
        
            self.output_file = os.path.join(os.getcwd(), os.path.basename(fname)) + '.png'
        
            fig.savefig(self.output_file, bbox_inches='tight')
        
        else:
        
            plt.show()
