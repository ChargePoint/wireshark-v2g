FROM ubuntu:22.04

# accept build arguments for docker
ARG PUID
ARG PGID

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update \
    && apt-get -y full-upgrade \
    && apt-get -y install sudo \
        software-properties-common \
        build-essential git cmake cmake-data

RUN add-apt-repository ppa:wireshark-dev/stable -y \
    && apt-get update -qq \
    && echo "wireshark-common wireshark-common/install-setuid boolean true" | \
       debconf-set-selections \
    && apt-get install -yqq cmake wireshark wireshark-dev tshark

# Add the docker user required with the build arguments to
# match the container id as needed
RUN groupadd -g ${PGID:-1001} docker ||:; \
    useradd -l -u ${PUID:-1001} -g ${PGID:-1001} -m docker && \
        echo 'docker ALL=NOPASSWD: ALL' > /etc/sudoers.d/docker

USER docker
WORKDIR /home/docker
