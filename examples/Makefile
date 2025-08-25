# Makefile for Easy Raw Socket API Examples

CC = gcc
CFLAGS = -Wall -O2
TARGETS = easy_capture easy_send easy_demo

# Default target
all: $(TARGETS)

# Build individual examples
easy_capture: easy_capture.c ../rawsock_easy.h ../rawsock.h
	$(CC) $(CFLAGS) -o $@ $<

easy_send: easy_send.c ../rawsock_easy.h ../rawsock.h
	$(CC) $(CFLAGS) -o $@ $<

easy_demo: easy_demo.c ../rawsock_easy.h ../rawsock.h
	$(CC) $(CFLAGS) -o $@ $<

# Clean build artifacts
clean:
	rm -f $(TARGETS)

# Run demo (requires sudo)
run-demo: easy_demo
	@echo "Running demo (requires root privileges)..."
	@sudo ./easy_demo

# Test capture (requires sudo)
test-capture: easy_capture
	@echo "Testing packet capture (requires root privileges)..."
	@echo "Press Ctrl+C to stop"
	@sudo ./easy_capture

# Test send (requires sudo)
test-send: easy_send
	@echo "Testing packet sending (requires root privileges)..."
	@sudo ./easy_send icmp 127.0.0.1 "Test ping"
	@sudo ./easy_send udp 127.0.0.1 12345 "Test UDP"

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build all examples (default)"
	@echo "  easy_capture - Build packet capture example"
	@echo "  easy_send    - Build packet sending example"
	@echo "  easy_demo    - Build comprehensive demo"
	@echo "  clean        - Remove built executables"
	@echo "  run-demo     - Run the demo (requires sudo)"
	@echo "  test-capture - Test packet capture (requires sudo)"
	@echo "  test-send    - Test packet sending (requires sudo)"
	@echo "  help         - Show this help message"

.PHONY: all clean run-demo test-capture test-send help