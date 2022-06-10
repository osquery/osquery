ARG OS_IMAGE

FROM alpine:3
ARG OSQUERY_URL
WORKDIR /download/
RUN wget $OSQUERY_URL -O osquery

FROM $OS_IMAGE
WORKDIR /root/
COPY --from=0 /download/osquery .
RUN dpkg -i osquery && rm -f osquery
