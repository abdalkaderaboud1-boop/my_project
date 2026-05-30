FROM alpine:3.19

# تثبيت nmap و python3 و masscan
RUN apk update && apk add --no-cache \
    python3 \
    nmap \
    nmap-scripts \
    masscan \
    bash

WORKDIR /app
RUN mkdir -p /app/results

# نسخ الـ Wrapper من المجلد الحالي إلى داخل الحاوية
COPY scanner_wrapper.py /app/scanner_wrapper.py

ENTRYPOINT ["python3", "/app/scanner_wrapper.py"]