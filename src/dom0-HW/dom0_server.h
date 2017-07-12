#pragma once

#include "tcp_socket.h"
#include <taskloader/taskloader_connection.h>
#include <parser/parser_connection.h>
#include <sched_controller_session/connection.h>

extern "C" {
#include <lwip/stats.h>
}

#include <util/xml_node.h>

// Get XML node attribute if it exists and copy default if not.
bool attribute_value(const Genode::Xml_node& config_node, const char* type, char* dst, const char* default_val, size_t max_len);

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
	Sched_controller::Connection _controller;
};
