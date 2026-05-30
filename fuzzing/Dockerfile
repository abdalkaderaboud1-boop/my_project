FROM golang:1.24-alpine

# تثبيت Python3 و Go و الأدوات المساعدة
RUN apk update && apk add --no-cache \
    python3 \
    git \
    bash \
    ca-certificates

# تثبيت الأدوات بالطريقة الرسمية بدلاً من بناءها من المصدر
RUN wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -zxvf ffuf_2.1.0_linux_amd64.tar.gz && \
    chmod +x ffuf && mv ffuf /usr/local/bin/ && \
    rm -rf ffuf_2.1.0_linux_amd64.tar.gz

RUN wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz && \
    tar -zxvf gobuster_Linux_x86_64.tar.gz && \
    chmod +x gobuster && mv gobuster /usr/local/bin/ && \
    rm -rf gobuster_Linux_x86_64.tar.gz

WORKDIR /app
RUN mkdir -p /app/results

# نسخ الـ Wrapper من المجلد الحالي إلى داخل الحاوية
COPY fuzzing_wrapper.py /app/fuzzing_wrapper.py

ENTRYPOINT ["python3", "/app/fuzzing_wrapper.py"]