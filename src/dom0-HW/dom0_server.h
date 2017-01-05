#pragma once

#include "tcp_socket.h"
#include <taskloader/taskloader_connection.h>
#include <parser/parser_connection.h>

extern "C" {
#include <lwip/stats.h>
}

class Dom0_server : public Tcp_socket
{
public:
	Dom0_server();

	~Dom0_server();

	int connect();

	void serve();

	void disconnect();

private:
	int _listen_socket;
	struct sockaddr_in _in_addr;
	sockaddr _target_addr;
	Taskloader_connection _task_loader;
	Parser_connection _parser;
};
