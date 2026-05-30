# استخدام Alpine كقاعدة خفيفة جداً
FROM golang:1.24-alpine
# تثبيت Go لبناء الأدوات، وبايثون للـ Wrapper، و Git للتحميل
RUN apk update && apk add --no-cache \
    python3 \
    bash \
    git \
    ca-certificates

# إعداد بيئة Go
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

# تثبيت الأدوات (Subfinder و Amass)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@latest

WORKDIR /app
RUN mkdir -p /app/results

# نسخ الـ Wrapper المخصص لهذه الحاوية
COPY recon_wrapper.py /app/recon_wrapper.py

ENTRYPOINT ["python3", "/app/recon_wrapper.py"]