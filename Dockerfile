FROM debian:trixie-slim AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git pkg-config nlohmann-json3-dev \
    libcurl4-openssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests
RUN cmake -S . -B out -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON && \
    cmake --build out --parallel && ctest --test-dir out --output-on-failure

FROM debian:trixie-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libcurl4t64 libstdc++6 libgcc-s1 bash curl git python3 make jq vim unzip tar && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system --gid 10001 dmcps && \
    useradd --system --uid 10001 --gid 10001 --home-dir /home/dmcps --create-home dmcps && \
    install -d -o 10001 -g 10001 /workspace /backups /var/lib/dmcps /tmp

COPY --from=build /build/out/dmcps /usr/local/bin/dmcps

ENV PORT=3000 \
    WORKSPACE_DIR=/workspace \
    BACKUP_DIR=/backups \
    CONFIG_PATH=/var/lib/dmcps/allowed_dirs.json
WORKDIR /workspace
USER 10001:10001
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/dmcps"]
CMD ["--http"]

