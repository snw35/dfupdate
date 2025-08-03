FROM python:3.12.5-alpine3.20

COPY dfupdate.py /dfupdate.py

COPY docker-entrypoint.sh /docker-entrypoint.sh

ENV DFUPDATE_VERSION 1.0.0
ENV REQUESTS_VERSION 2.32.3
ENV DOCKERFILE_PARSE_VERSION 2.0.1

RUN apk --upgrade --no-cache add \
    bash \
  && apk --no-cache --virtual build.deps add \
    build-base \
  && pip3 install --no-cache-dir \
    requests==${REQUESTS_VERSION} \
    dockerfile_parse==${DOCKERFILE_PARSE_VERSION} \
  && apk del build.deps \
  && chmod +x /dfupdate.py \
  && chmod +x /docker-entrypoint.sh

WORKDIR /data

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/dfupdate.py"]
