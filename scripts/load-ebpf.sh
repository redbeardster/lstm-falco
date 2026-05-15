#!/bin/bash

set -e

echo "🔧 Загрузка eBPF программ для seccomp мониторинга"

# Проверка прав
if [[ $EUID -ne 0 ]]; then
   echo "❌ Этот скрипт должен быть запущен с root правами" 
   exit 1
fi

# Проверка поддержки eBPF
if ! mount | grep -q "bpffs"; then
    echo "Монтирование bpffs..."
    mount -t bpf bpf /sys/fs/bpf/
fi

# Компиляция eBPF программ
echo "📦 Компиляция eBPF программ..."
cd ebpf
cargo build --release --target bpfel-unknown-none

# Загрузка eBPF программ
echo "⬆️ Загрузка seccomp monitor..."
bpftool prog load ./target/bpfel-unknown-none/release/seccomp_monitor.o \
    /sys/fs/bpf/seccomp_monitor type tracepoint

# Прикрепление к трейспоинтам
echo "🔗 Прикрепление к системным вызовам..."
bpftool prog attach pinned /sys/fs/bpf/seccomp_monitor \
    tracepoint syscalls sys_enter

# Проверка загрузки
echo "✅ Статус eBPF программ:"
bpftool prog list | grep -A 3 "seccomp"

echo "🚀 eBPF мониторинг успешно запущен!"
