# Multi-stage build для совместимости GLIBC

# Stage 1: Builder
FROM rust:1.83-bookworm as builder

WORKDIR /usr/src/app

# Установка зависимостей для сборки
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Копируем все файлы проекта
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Собираем проект (используем nightly для edition2024)
# Поддержка build arg для features
ARG FEATURES=""
RUN rustup default nightly && \
    if [ -n "$FEATURES" ]; then \
        echo "Building with features: $FEATURES" && \
        cargo build --release --features "$FEATURES"; \
    else \
        echo "Building without additional features" && \
        cargo build --release; \
    fi

# Stage 2: Runtime
FROM debian:bookworm-slim

# Установка runtime зависимостей
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Создаем непривилегированного пользователя
RUN useradd -m -u 1000 security && \
    mkdir -p /opt/seccomp/ebpf && \
    chown -R security:security /opt/seccomp

WORKDIR /app

# Копируем бинарник из builder
COPY --from=builder /usr/src/app/target/release/enterprise-security-stack /app/

# Копируем конфигурацию
COPY k8s/ /app/k8s/
COPY falco/ /app/falco/

# Меняем владельца
RUN chown -R security:security /app

USER security

# Expose API port
EXPOSE 3000 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Запуск приложения
CMD ["./enterprise-security-stack"]
