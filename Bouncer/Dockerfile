#/*
#==================================================================================
#
#        Copyright (c) 2019-2020 AT&T Intellectual Property.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#==================================================================================
# */

ARG SCHEMA_PATH=schemas
ARG STAGE_DIR=/tmp/bouncer-xapp

#==================================================================================
FROM nexus3.o-ran-sc.org:10002/o-ran-sc/bldr-ubuntu20-c-go:1.0.0 as ricbuild

ARG SCHEMA_PATH
ARG STAGE_DIR

# Install necessary packages
RUN apt-get update  \
    && apt-get install -y \
    cmake \
    git \
    build-essential \
    automake \
    autoconf-archive \
    autoconf \
    pkg-config \
    gawk \
    libtool \
    wget \
    zlib1g-dev \
    libffi-dev \
    libcpprest-dev \
    cpputest \
    libhiredis-dev \
    libcurl4-openssl-dev \
    && apt-get clean

WORKDIR ${STAGE_DIR}

# Install mdclog using debian package hosted at packagecloud.io
ARG MDC_VER=0.1.4-1
RUN wget -nv --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/mdclog_${MDC_VER}_amd64.deb/download.deb && \
    wget -nv --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/mdclog-dev_${MDC_VER}_amd64.deb/download.deb && \
    dpkg -i mdclog_${MDC_VER}_amd64.deb mdclog-dev_${MDC_VER}_amd64.deb

# Install RMR using debian package hosted at packagecloud.io
ARG RMR_VER=4.8.3
RUN wget -nv --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr_${RMR_VER}_amd64.deb/download.deb && \
    wget -nv --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rmr-dev_${RMR_VER}_amd64.deb/download.deb && \
    dpkg -i rmr_${RMR_VER}_amd64.deb rmr-dev_${RMR_VER}_amd64.deb

#Install RNIB libraries
ARG RNIB_VER=1.2.5
RUN wget -nv --content-disposition https://packagecloud.io/o-ran-sc/release/packages/debian/stretch/rnib_${RNIB_VER}_all.deb/download.deb && \
    dpkg -i rnib_${RNIB_VER}_all.deb

RUN git clone https://github.com/azadkuh/nlohmann_json_release.git && \
    mkdir /usr/local/include/nlohmann && \
    cp nlohmann_json_release/json.hpp /usr/local/include/nlohmann

## Install SDL Libraries
RUN git clone https://gerrit.o-ran-sc.org/r/ric-plt/dbaas && \
    cd dbaas/redismodule && \
    ./autogen.sh && \
    ./configure && \
    make -j `nproc` all && \
    make install

RUN git clone https://gerrit.o-ran-sc.org/r/ric-plt/sdl && \
    cd sdl && \
    ./autogen.sh && \
    ./configure && \
    make -j `nproc` all && \
    make install

## Install rapidjson
RUN git clone https://github.com/Tencent/rapidjson && \
    cp -r rapidjson/include/rapidjson /usr/local/include/
    # cd rapidjson && \
    # mkdir build && \
    # cd build && \
    # cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    # make -j 4 install && \
    # cd ${STAGE_DIR} && \
    # rm -rf rapidjson


##-----------------------------------
# Now install the program
#------------------------------------
COPY ./ ${STAGE_DIR}

RUN export CPATH=$CPATH:/usr/local/include && \
    cd src && \
    # sh does not have source, so we use .
    # . ./xapp_env.sh \
    # source ./xapp_env.sh \
    make clean && \
    make -j `nproc` install

COPY ${SCHEMA_PATH}/* init/routes.txt init/config-map.yaml schemas/a1-policy-schema.json schemas/a1-payload-schema.json /etc/xapp/
# COPY init/init_script.py /etc/xapp/init_script.py


#---------------------------------------------
# #Build the final version
FROM ubuntu:20.04

ARG STAGE_DIR

RUN apt-get update && \
    apt-get install -y libcpprest2.10 libhiredis0.14 tcpdump iproute2 && \
    apt-get clean

## copy just the needed libraries install them into the final image
COPY --from=ricbuild ${STAGE_DIR}/rmr_*.deb ${STAGE_DIR}/mdclog_*.deb /tmp/
RUN dpkg -i /tmp/*.deb && \
    rm -f /tmp/*.deb

COPY --from=ricbuild /etc/xapp/* /etc/xapp/
COPY --from=ricbuild /usr/local/bin/b_xapp_main /usr/local/bin/b_xapp_main

##ENV  PYTHONHOME=/opt/python3 \
##     PYTHONPATH=/opt/python3 \
ENV RMR_RTG_SVC="9999" \
    RMR_SEED_RT="/etc/xapp/routes.txt" \
    LD_LIBRARY_PATH="/usr/local/lib:/usr/local/libexec" \
    VERBOSE=0 \
    CONFIG_MAP_NAME=/etc/xapp/config-map.yaml \
    CONFIG_FILE=/opt/ric/config/config-file.json \
    A1_POLICY_SCHEMA_FILE=/etc/xapp/a1-policy-schema.json \
    A1_PAYLOAD_SCHEMA_FILE=/etc/xapp/a1-payload-schema.json

# CMD python3 /etc/xapp/init_script.py $CONFIG_FILE
# CMD ["sleep", "360000"]
CMD ["b_xapp_main"]
# CMD while true; do sleep 3600; done

