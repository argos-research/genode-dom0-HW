TARGET = dom0-HW
SRC_CC = main.cc dom0_server.cc
LIBS = base lwip libc stdcxx

INC_DIR += $(REP_DIR)/../genode/repos/libports/include/lwip
