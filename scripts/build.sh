#!/bin/bash

# 項目名稱
APP_NAME="quicvpn"
# 輸出目錄
OUTPUT_DIR="bin"
# 版本號 (可選，預設為當前時間戳)
VERSION=$(date +%Y%m%d_%H%M%S)

# 建立輸出目錄
mkdir -p $OUTPUT_DIR

# 清理舊的編譯檔案
echo "Cleaning old binaries..."
rm -rf $OUTPUT_DIR/*
#go mod tidy
#go get -u

# 定義要編譯的目標平台 (OS/Arch)
# 注意：由於本項目依賴 Linux 的 TAP 和 Netlink，非 Linux 平台的編譯僅用於程式碼檢查，無法實際運行
PLATFORMS=(
    "linux/amd64"   # 傳統 64 位伺服器
    "linux/386"     # 傳統 32 位伺服器
    "linux/arm64"   # 新型伺服器 (如 AWS Graviton), 樹莓派 4/5
    "linux/arm"     # 嵌入式設備, 舊款樹莓派
    "linux/mipsle"  # 路由器常見架構 (Little Endian)
    "linux/mips"    # 路由器常見架構 (Big Endian)
)

echo "Starting build process for $APP_NAME..."

for PLATFORM in "${PLATFORMS[@]}"
do
    # 拆分 OS 和 ARCH
    IFS="/" read -r -a SPLIT <<< "$PLATFORM"
    GOOS=${SPLIT[0]}
    GOARCH=${SPLIT[1]}
    
    # 定義輸出檔案名稱
    OUTPUT_NAME="${APP_NAME}_${GOOS}_${GOARCH}"
    
    # 執行編譯
    # CGO_ENABLED=0: 靜態編譯，不依賴系統 libc，提高移植性
    # -ldflags="-s -w": 壓縮體積，移除符號表和調試資訊
    echo "Building $PLATFORM..."
    env CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "-s -w" \
        -o "$OUTPUT_DIR/$OUTPUT_NAME" *.go

    if [ $? -ne 0 ]; then
        echo "Error building $PLATFORM"
        exit 1
    fi
done

echo "---------------------------------------"
echo "Build complete! Check the '$OUTPUT_DIR' directory."
ls -lh $OUTPUT_DIR