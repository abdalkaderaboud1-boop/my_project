FROM alpine:3.19

# تثبيت Python3 و Go و الأدوات المساعدة
RUN apk update && apk add --no-cache \
    python3 \
    go \
    git \
    bash \
    ca-certificates

# إعداد بيئة Go لتثبيت أدوات الفuzzing
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

# تثبيت الأدوات (ffuf و gobuster)
RUN go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/OJ/gobuster/v3@latest

WORKDIR /app
RUN mkdir -p /app/results

# نسخ الـ Wrapper من المجلد الحالي إلى داخل الحاوية
COPY fuzzing_wrapper.py /app/fuzzing_wrapper.py

ENTRYPOINT ["python3", "/app/fuzzing_wrapper.py"]