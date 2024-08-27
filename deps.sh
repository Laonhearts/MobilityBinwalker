#!/bin/bash

# --yes 명령줄 인수가 제공되면 yes/no 프롬프트를 건너뛰도록 설정합니다.
if [ "$1" = "--yes" ]
then
    YES=1
else
    YES=0
fi

# 스크립트가 오류 시 종료되도록 하고, 사용되지 않은 변수를 사용하면 오류를 발생시킵니다.
set -eu
set -o nounset
set -x

# lsb_release 명령이 없으면, 이를 대신하는 함수를 정의합니다.
if ! which lsb_release > /dev/null
then
    function lsb_release {
        if [ -f /etc/os-release ]
        then
            [[ "$1" = "-i" ]] && cat /etc/os-release | grep ^"ID" | cut -d= -f 2
            [[ "$1" = "-r" ]] && cat /etc/os-release | grep "VERSION_ID" | cut -d= -d'"' -f 2
        elif [ -f /etc/lsb-release ]
        then
            [[ "$1" = "-i" ]] && cat /etc/lsb-release | grep "DISTRIB_ID" | cut -d= -f 2
            [[ "$1" = "-r" ]] && cat /etc/lsb-release | grep "DISTRIB_RELEASE" | cut -d= -f 2
        else
            echo Unknown
        fi
    }
fi

# YES 플래그가 설정되지 않은 경우, 배포판과 버전을 감지합니다.
if [ $YES -eq 0 ]
then
    distro="${1:-$(lsb_release -i|cut -f 2)}"
    distro_version="${1:-$(lsb_release -r|cut -f 2|cut -c1-2)}"
else
    distro="${2:-$(lsb_release -i|cut -f 2)}"
    distro_version="${2:-$(lsb_release -r|cut -f 2|cut -c1-2)}"
fi

# 필요한 유틸리티와 패키지를 정의합니다.
REQUIRED_UTILS="wget tar python"
APTCMD="apt"
APTGETCMD="apt-get"
YUMCMD="yum"

# 배포판과 버전에 따른 설치할 패키지를 정의합니다.
if [ $distro = "Kali" ]
then
    APT_CANDIDATES="git locales build-essential qt5base-dev mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract util-linux firmware-mod-kit cramfsswap squashfs-tools zlib1g-dev liblzma-dev liblzo2-dev sleuthkit default-jdk lzop cpio"
elif [ $distro_version = "14" ]
then
    APT_CANDIDATES="git locales build-essential libqt4-opengl mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsprogs cramfsswap squashfs-tools zlib1g-dev liblzma-dev liblzo2-dev sleuthkit default-jdk lzop srecord cpio"
elif [ $distro_version = "15" ]
then
    APT_CANDIDATES="git locales build-essential libqt4-opengl mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsprogs cramfsswap squashfs-tools zlib1g-dev liblzma-dev liblzo2-dev sleuthkit default-jdk lzop srecord cpio"
elif [ $distro_version = "16" ]
then
    APT_CANDIDATES="git locales build-essential libqt4-opengl mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsprogs cramfsswap squashfs-tools zlib1g-dev liblzma-dev liblzo2-dev sleuthkit default-jdk lzop srecord cpio"
elif [ $distro_version = "18" ]
then
    APT_CANDIDATES="git locales build-essential libqt4-opengl mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsswap squashfs-tools zlib1g-dev liblzma-dev liblzo2-dev sleuthkit default-jdk lzop srecord cpio"
else
    APT_CANDIDATES="git locales build-essential qtbase5-dev mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsswap squashfs-tools zlib1g-dev liblzma-dev liblzo2-dev sleuthkit default-jdk lzop srecord cpio"
fi

# YUM을 사용하는 경우 설치할 패키지를 정의합니다.
PYTHON3_APT_CANDIDATES=""
PYTHON3_YUM_CANDIDATES=""
YUM_CANDIDATES="git gcc gcc-c++ make openssl-devel qtwebkit-devel qt-devel gzip bzip2 tar arj p7zip p7zip-plugins cabextract squashfs-tools zlib zlib-devel lzo lzo-devel xz xz-compat-libs xz-libs xz-devel xz-lzma-compat python-backports-lzma lzip pyliblzma perl-Compress-Raw-Lzma lzop srecord"
PYTHON="$(which python3)"

# 루트 권한이 있는지 확인합니다.
if [ $UID -eq 0 ]
then
    echo "UID is 0, sudo not required"
    SUDO=""
else
    SUDO="sudo -E"
    REQUIRED_UTILS="sudo $REQUIRED_UTILS"
fi

# 필요한 유틸리티를 설치하는 함수를 정의합니다.
function install_yaffshiv
{
    git clone --quiet --depth 1 --branch "master" https://github.com/devttys0/yaffshiv
    (cd yaffshiv && $SUDO $PYTHON setup.py install)
    $SUDO rm -rf yaffshiv
}

function install_sasquatch
{
    git clone --quiet --depth 1 --branch "master" https://github.com/devttys0/sasquatch
    (cd sasquatch && $SUDO ./build.sh)
    $SUDO rm -rf sasquatch
}

function install_jefferson
{
    git clone --quiet --depth 1 --branch "master" https://github.com/sviehb/jefferson
    (cd jefferson && $SUDO $PYTHON -mpip install -r requirements.txt && $SUDO $PYTHON setup.py install)
    $SUDO rm -rf jefferson
}

function install_cramfstools
{
  # cramfs 도구를 다운로드하여 $INSTALL_LOCATION에 설치합니다.
  TIME=`date +%s`
  INSTALL_LOCATION=/usr/local/bin

  # cramfs 도구를 GitHub에서 클론합니다.
  git clone --quiet --depth 1 --branch "master" https://github.com/npitre/cramfs-tools
  # make 및 설치
  (cd cramfs-tools \
  && make \
  && $SUDO install mkcramfs $INSTALL_LOCATION \
  && $SUDO install cramfsck $INSTALL_LOCATION)

  rm -rf cramfs-tools
}

function install_ubireader
{
    git clone --quiet --depth 1 --branch "master" https://github.com/jrspruitt/ubi_reader
    (cd ubi_reader && $SUDO $PYTHON setup.py install)
    $SUDO rm -rf ubi_reader
}

# pip 패키지를 설치하는 함수를 정의합니다.
function install_pip_package
{
    PACKAGE="$1"
    $SUDO $PYTHON -mpip install $PACKAGE
}

# 파일 경로를 찾는 함수를 정의합니다.
function find_path
{
    FILE_NAME="$1"

    echo -ne "checking for $FILE_NAME..."
    which $FILE_NAME > /dev/null
    if [ $? -eq 0 ]
    then
        echo "yes"
        return 0
    else
        echo "no"
        return 1
    fi
}

# 사용자가 스크립트를 실행하려는지 확인합니다.
if [ $YES -eq 0 ]
then
    echo ""
    echo "WARNING: 이 스크립트는 binwalk의 모든 필수 및 선택적 종속성을 다운로드하고 설치합니다."
    echo "         이 스크립트는 Debian 기반 시스템에서만 테스트되었으며, 해당 시스템에서만 사용할 수 있습니다."
    echo "         일부 종속성은 비보안(HTTP) 프로토콜을 통해 다운로드됩니다."
    echo "         이 스크립트는 인터넷 접속이 필요합니다."
    echo "         이 스크립트는 루트 권한이 필요합니다."
    echo ""
    if [ $distro != Unknown ]
    then
        echo "         $distro $distro_version 감지됨"
    else
        echo "WARNING: 배포판을 감지할 수 없으며, 기본 패키지 관리자 설정을 사용합니다."
    fi
    echo ""
    echo -n "계속하시겠습니까 [y/N]? "
    read YN
    if [ "$(echo "$YN" | grep -i -e 'y' -e 'yes')" == "" ]
    then
        echo "종료 중..."
        exit 1
    fi
elif [ $distro != Unknown ]
then
     echo "$distro $distro_version 감지됨"
else
    echo "WARNING: 배포판을 감지할 수 없으며, 기본 패키지 관리자 설정을 사용합니다."
fi

# 필요한 유틸리티가 설치되어 있는지 확인합니다.
NEEDED_UTILS=""
for UTIL in $REQUIRED_UTILS
do
    find_path $UTIL
    if [ $? -eq 1 ]
    then
        NEEDED_UTILS="$NEEDED_UTILS $UTIL"
    fi
done

# 지원되는 패키지 관리자를 확인하고 PKG_* 환경 변수를 설정합니다.
find_path $APTCMD
if [ $? -eq 1 ]
then
    find_path $APTGETCMD
    if [ $? -eq 1 ]
    then
        find_path $YUMCMD
        if [ $? -eq 1 ]
        then
            NEEDED_UTILS="$NEEDED_UTILS $APTCMD/$APTGETCMD/$YUMCMD"
        else
            PKGCMD="$YUMCMD"
            PKGCMD_OPTS="-y install"
            PKG_CANDIDATES="$YUM_CANDIDATES"
            PKG_PYTHON3_CANDIDATES="$PYTHON3_YUM_CANDIDATES"
        fi
    else
        PKGCMD="$APTGETCMD"
        PKGCMD_OPTS="install -y"
        PKG_CANDIDATES="$APT_CANDIDATES"
        PKG_PYTHON3_CANDIDATES="$PYTHON3_APT_CANDIDATES"
    fi
else
    if "$APTCMD" install -s -y dpkg > /dev/null
    then
        PKGCMD="$APTCMD"
        PKGCMD_OPTS="install -y"
        PKG_CANDIDATES="$APT_CANDIDATES"
        PKG_PYTHON3_CANDIDATES="$PYTHON3_APT_CANDIDATES"
    else
        PKGCMD="$APTGETCMD"
        PKGCMD_OPTS="install -y"
        PKG_CANDIDATES="$APT_CANDIDATES"
        PKG_PYTHON3_CANDIDATES="$PYTHON3_APT_CANDIDATES"
    fi
fi

if [ "$NEEDED_UTILS" != "" ]
then
    echo "다음의 필수 유틸리티를 설치하십시오: $NEEDED_UTILS"
    exit 1
fi

# 설치 작업을 수행합니다.
cd /tmp
$SUDO $PKGCMD $PKGCMD_OPTS $PKG_CANDIDATES
if [ $? -ne 0 ]
    then
    echo "패키지 설치 실패: $PKG_CANDIDATES"
    exit 1
fi
install_pip_package "setuptools matplotlib capstone pycryptodome gnupg tk"
install_sasquatch
install_yaffshiv
install_jefferson
install_ubireader

if [ $distro_version = "18" ]
then
install_cramfstools
fi
