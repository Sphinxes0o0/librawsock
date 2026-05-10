FROM gcc:13

# Install build essentials and netcat for testing
RUN apt-get update && apt-get install -y \
    build-essential \
    netcat-openbsd \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy source
COPY . .

# Compile the C library and tests
RUN gcc -c rawsock.c -o rawsock.o && \
    gcc -o tests/offline_unit_test tests/offline_unit_test.c && \
    g++ -std=c++11 -o examples/simple_send      examples/simple_send.cpp      rawsock.o && \
    g++ -std=c++11 -o examples/simple_capture   examples/simple_capture.cpp   rawsock.o && \
    g++ -std=c++11 -o examples/arp_scan         examples/arp_scan.cpp         rawsock.o && \
    g++ -std=c++11 -o examples/ping_sweep       examples/ping_sweep.cpp       rawsock.o && \
    g++ -std=c++11 -o examples/arp_monitor      examples/arp_monitor.cpp      rawsock.o && \
    g++ -std=c++11 -o examples/packet_logger    examples/packet_logger.cpp    rawsock.o

# Default command: run offline unit tests
CMD ["./tests/offline_unit_test"]
