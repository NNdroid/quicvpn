#!/bin/bash

# 获取当前机器的真实操作系统和架构
HOST_OS=$(go env GOHOSTOS)
HOST_ARCH=$(go env GOHOSTARCH)

# 强制将编译环境变量设为本机配置
export GOOS=$HOST_OS
export GOARCH=$HOST_ARCH

echo -e "\033[36mSet GOOS=$HOST_OS, GOARCH=$HOST_ARCH\033[0m"
echo -e "\033[32mStarting Benchmark natively...\033[0m"

go test -v -run .
go test -bench . -benchmem