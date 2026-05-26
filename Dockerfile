FROM ghcr.io/zaproxy/zaproxy:stable

EXPOSE 10000

CMD zap.sh -daemon -host 0.0.0.0 -port 10000 -config api.disablekey=true
