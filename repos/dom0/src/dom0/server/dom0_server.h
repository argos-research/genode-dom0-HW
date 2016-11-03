#pragma once

#include "tcp_socket.h"
#include <dom0/task_manager_connection.h>

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
	Task_manager_connection _task_manager;
};
