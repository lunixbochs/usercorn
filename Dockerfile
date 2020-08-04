FROM ubuntu:18.04
RUN apt update && \
    apt -y install --no-install-recommends gcc-multilib g++-multilib git cmake \
                                           gcc g++ pkg-config libglib2.0-dev curl

# Install python3.8
RUN apt -y install --no-install-recommends software-properties-common \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt update \
    && apt -y install python3.8-dev python3.8-venv python3-pip
RUN python3.8 -m venv /root/py38
ENV PATH="/root/py38/bin:${PATH}"

RUN git clone -b unstable https://github.com/lunixbochs/usercorn.git /usercorn
WORKDIR /usercorn
RUN make deps
RUN make
RUN ln -s /usercorn/usercorn /usr/bin/
