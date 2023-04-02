FROM python:3.11.2-alpine3.17

COPY dfupdate.py /dfupdate.py

COPY docker-entrypoint.sh /docker-entrypoint.sh

ENV DFUPDATE_VERSION 0.2.0
ENV REQUESTS_VERSION 2.28.2
ENV DOCKERFILE_PARSE_VERSION 2.0.0

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
