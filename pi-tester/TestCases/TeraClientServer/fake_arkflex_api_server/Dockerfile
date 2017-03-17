FROM ubuntu:trusty
MAINTAINER Kent Chen <kent.chen@hopebaytech.com>

ENV base_dir /opt/fake_server

RUN apt-get update
RUN (DEBIAN_FRONTEND=noninteractive apt-get install -y python python-pip)
RUN pip install requests

ADD fake_arkflex_api_server.py ${base_dir}/fake_arkflex_api_server.py
RUN python ${base_dir}/fake_arkflex_api_server.py

EXPOSE 5000

WORKDIR ${base_dir}