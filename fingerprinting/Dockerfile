FROM debian:bookworm-slim

# تحديث القوائم وتثبيت الأدوات الأساسية
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    ruby ruby-bundler \
    golang-go git \
    bash curl wget ca-certificates \
    build-essential \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# تحديث pip
RUN python3 -m pip install --no-cache-dir --break-system-packages --upgrade pip

# تثبيت wafw00f
RUN pip3 install --no-cache-dir --break-system-packages wafw00f

ENV GOPATH=/root/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN go install -v github.com/tomnomnom/httprobe@latest

WORKDIR /app
RUN mkdir -p /app/results

COPY fingerprinting_wrapper.py /app/fingerprinting_wrapper.py
ENTRYPOINT ["python3", "/app/fingerprinting_wrapper.py"]