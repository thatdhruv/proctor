# Build and run the Proctor execution core (and its Python client) in one image.
#   docker build -f core/Dockerfile -t proctor-core .
#   docker run --rm --privileged proctor-core python3 core/tests/run_tests.py /opt/proctor/bin
FROM ubuntu:22.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ make && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY core/ core/
RUN make -C core -j"$(nproc)" BUILD=/opt/proctor/bin

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/proctor/bin /opt/proctor/bin
COPY core/tests /opt/proctor/core/tests
COPY python /opt/proctor/python
WORKDIR /opt/proctor
ENV PROCTOR_CORE_BUILD=/opt/proctor/bin PYTHONPATH=/opt/proctor/python
CMD ["/opt/proctor/bin/proctord", "--socket", "/run/proctord.sock", "--pool", "8", "--metrics-port", "9464"]
