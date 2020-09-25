FROM python:3.8.6-alpine3.12

COPY dfupdate.py /dfupdate.py

COPY docker-entrypoint.sh /docker-entrypoint.sh

ENV REQUESTS_VERSION 2.24.0
ENV DOCKERFILE_PARSE_VERSION 1.0.0

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
