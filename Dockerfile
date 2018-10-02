FROM python:3.5-alpine
LABEL maintainer="Mostafa Hussein <mostafa.hussein91@gmail.com>"
RUN apk add --no-cache gcc musl-dev libxml2-dev libxslt-dev openssl
ADD ./ /home/fuxploider
WORKDIR /home/fuxploider
RUN pip3 install -r requirements.txt
RUN adduser -D fuxploider -H -h /home/fuxploider && chown fuxploider:fuxploider /home/fuxploider -R
USER fuxploider
ENTRYPOINT ["python", "fuxploider.py"]
CMD ["-h"]
