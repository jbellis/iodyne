#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

export LC_ALL=C
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

for target_arch in x86 arm64; do
    clang \
        -target bpfel \
        -D__TARGET_ARCH_${target_arch} \
        -O2 -g -Wall -Werror \
        -fdebug-prefix-map="$(pwd)"=. \
        -c disk_latency.bpf.c \
        -o "disk_latency-${target_arch}.bpf.o"
    clang \
        -target bpfel \
        -D__TARGET_ARCH_${target_arch} \
        -O2 -g -Wall -Werror \
        -fdebug-prefix-map="$(pwd)"=. \
        -c vfs_activity.bpf.c \
        -o "vfs_activity-${target_arch}.bpf.o"
done

# Retain the original object name for existing packaging checks. Release code
# selects the explicit architecture variant below.
cp disk_latency-x86.bpf.o disk_latency.bpf.o
