FROM python:3.8.1-alpine3.11

COPY dfupdate.py /dfupdate.py

COPY docker-entrypoint.sh /docker-entrypoint.sh

ENV REQUESTS_VERSION 2.23.0
ENV DOCKERFILE_PARSE_VERSION 0.0.16

RUN apk --upgrade --no-cache add \
    bash \
  && apk --no-cache --virtual build.deps add \
    build-base \
  && pip3 install --no-cache-dir \
    requests==${REQUESTS_VERSION} \
    dockerfile_parse==${DOCKERFILE_PARSE_VERSION} \
  && apk del build.deps \
  && chmod +x /dfupdate.py \
  && chmod +x /docker-entrypoint.sh \
  && python3 /dfupdate.py

WORKDIR /data

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/dfupdate.py"]
