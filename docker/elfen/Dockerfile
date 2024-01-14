#Copyright (C) 2023-2024 Nikhil Ashok Hegde (@ka1do9)
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

FROM python:3.8.16-bullseye

ENV PIP_DISABLE_PIP_VERSION_CHECK 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y vim git

# Install Graphviz
RUN apt-get install -y graphviz graphviz-dev

# Install Yara
WORKDIR /tmp
RUN apt-get install -y automake libtool make gcc pkg-config libmagic-dev
RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.2.3.tar.gz
RUN tar xzf v4.2.3.tar.gz
WORKDIR /tmp/yara-4.2.3
RUN ./bootstrap.sh
RUN ./configure --enable-magic
RUN make
RUN make install
RUN echo "/usr/local/lib" >> /etc/ld.so.conf
RUN ldconfig

# Install Golang
WORKDIR /tmp
RUN wget https://go.dev/dl/go1.19.5.linux-amd64.tar.gz
RUN gzip -d go1.19.5.linux-amd64.tar.gz
RUN tar -xf go1.19.5.linux-amd64.tar
RUN mv go /usr/local
ENV PATH="${PATH}:/usr/local/go/bin"

# Install elfinfo
RUN go install github.com/xyproto/elfinfo@latest
RUN mv /root/go/bin/elfinfo /usr/local/bin

# Install QEMU
RUN apt-get install -y qemu qemu-system-mips qemu-system-x86 qemu-system-ppc64 \
    qemu-system-misc libvirt-daemon qemu-system-arm qemu-efi

# Cleanup unnecessary dependencies
RUN apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /elfen

# Install dependencies
COPY ./requirements.txt .
RUN pip install -r ./requirements.txt

# Copy ELFEN into container
COPY . /elfen
