FROM ubuntu:trusty
MAINTAINER Kent Chen <kent.chen@hopebaytech.com>

ENV base_dir /opt/fake_server

RUN apt-get update
RUN (DEBIAN_FRONTEND=noninteractive apt-get install -y python python-pip)
RUN pip install requests

ADD fake_swift_server.py ${base_dir}/fake_swift_server.py

EXPOSE 8080

WORKDIR ${base_dir}