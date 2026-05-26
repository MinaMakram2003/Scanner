FROM ghcr.io/zaproxy/zaproxy:stable

USER root

RUN apt update && apt install -y python3 python3-pip

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD zap.sh -daemon -host 0.0.0.0 -port 8082 -config api.disablekey=true && \
    uvicorn main:app --host 0.0.0.0 --port 10000
