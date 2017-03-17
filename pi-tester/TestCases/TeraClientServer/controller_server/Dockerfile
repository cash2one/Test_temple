FROM ubuntu:trusty
MAINTAINER Kent Chen <kent.chen@hopebaytech.com>

ENV base_dir /opt/fake_server

RUN apt-get update
RUN (DEBIAN_FRONTEND=noninteractive apt-get install -y python python-pip)
RUN pip install requests

ADD controller_server.py ${base_dir}/controller_server.py

EXPOSE 7070

WORKDIR ${base_dir}

CMD ["python", "controller_server.py"]
