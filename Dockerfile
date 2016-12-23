FROM ubuntu:16.04
MAINTAINER intel.com


# define proxy environment variables to build image
# if environment requires
#ENV http_proxy 'http://<proxy server>:<port>'
#ENV https_proxy 'http://<proxy server>:<port>'
#ENV ftp_proxy 'http://<proxy server>:<port>'
#ENV socks_proxy 'socks://<proxy server>:<port>'
#ENV no_proxy 'localhost,127.0.0.1,.<example.com>'

# create apt proxy
#RUN echo 'Acquire::http::Proxy "<proxy server>";' >>/etc/apt/apt.conf.d/20proxy




# This will prevent questions from being asked during the install
ENV DEBIAN_FRONTEND=noninteractive
# update and install packages required by TAF
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    sudo \
    ca-certificates \
    curl \
    gcc \
    git \
    libpq-dev \
    pkg-config \
    libssl-dev \
    libffi-dev \
    libpcap-dev \
    xsltproc \
    smitools \
    sshpass \
    openjdk-8-jre \
    libc6-i386 \
    libcurl4-openssl-dev \
    tk8.6 \
    tcl8.6 \
    tclx \
    libzmq3-dev \
    iproute2 \
    iputils-ping \
    wget \
    openssh-client \
    doxygen \
    doxygen-latex \
    rsync \
    # install python
    python3 \
    python3-dev \
    # we can't use ubuntu pip because it is old
    python3-tk \
    && apt-get autoremove \
    && apt-get clean


# need to specify path to Ixia client library and
# copy ixia files where X.XX is Ixia version
#ARG IXNET_PATH="share/Tools/IXIA/IxNetwork_X.XX"
#ARG IXNET_FILE="IxNetworkTclClient_X.XX.Linux.bin.tgz"
# do it all at once and remove tarball after to save space in layers
#RUN mkdir -p /opt ; wget -nv $IXIA_MIRROR_URL/$IXNET_PATH/$IXNET_FILE -P /opt/ && tar -C /opt/ -xvf /opt/$IXNET_FILE && ls -l /opt/${IXNET_FILE%????} && /opt/${IXNET_FILE%????} -DUSER_INSTALL_DIR=/opt/ixos -i silent && rm /opt/$IXNET_FILE


# set git proxy
#RUN git config --global http.proxy <proxy server>:<port>; \
#git config --global https.proxy <proxy server>:<port>



# download the latest pip
RUN curl -s "https://bootstrap.pypa.io/get-pip.py" | python3 -

# install ci requirements
RUN echo '# Use 2.13 version instead of 2.14 based on issue https://github.com/eliben/pycparser/issues/147 \n\
pycparser==2.13 \n\
cffi \n\
git-review \n\
flake8 \n\
pylint \n\
setuptools_scm \n\
pytest \n\
pytest-xdist \n\
# for doxygen \n\
doxypy \n\
mock \n\
' > /root/requirements.txt && pip install --upgrade -r /root/requirements.txt && rm /root/requirements.txt && rm -rf /root/.cache/pip


# always need /etc/environment for IXIA and TCL vars
COPY docker_environment_variables /etc/environment

ARG TAF_ROOT=/root/taf
# copy TAF repo to docker image
COPY /  $TAF_ROOT/

# install Python libraries required by TAF CI
RUN test -r "$TAF_ROOT/unittests/ci/requirements.txt" && pip install -r $TAF_ROOT/unittests/ci/requirements.txt || true

# install Python libraries required by TAF
RUN pip install -r $TAF_ROOT/requirements.txt




# copy TRex client API library
ARG TREX_VERSION=v2.00
ARG TREX_TMP_PATH=/tmp/trex
ARG TREX_WEB_URL=http://trex-tgn.cisco.com/trex/release
ENV TREX_CLIENT_LIB=/opt/trex_client/stl
RUN mkdir "$TREX_TMP_PATH" && wget -nv --no-cache "$TREX_WEB_URL/$TREX_VERSION.tar.gz" -P "$TREX_TMP_PATH" \
&& tar -C "$TREX_TMP_PATH" -xvf "$TREX_TMP_PATH/$TREX_VERSION.tar.gz" \
&& tar -C /opt/ -xvf "$TREX_TMP_PATH/$TREX_VERSION/trex_client_$TREX_VERSION.tar.gz" \
&& rm "$TREX_TMP_PATH/$TREX_VERSION.tar.gz" && rm "$TREX_TMP_PATH/$TREX_VERSION/trex_client_$TREX_VERSION.tar.gz"






# entry point to login as root user for TAF container
ENTRYPOINT login -f root && bash
