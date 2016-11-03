TARGET = dom0
SRC_CC = main.cc tcp_socket.cc dom0_server.cc config.cc
LIBS = base config lwip libc stdcxx

INC_DIR += $(REP_DIR)/../libports/include/lwip
