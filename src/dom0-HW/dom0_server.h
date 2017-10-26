#pragma once

#include "tcp_socket.h"
#include <taskloader/taskloader_connection.h>
#include <parser/parser_connection.h>
#include <timer_session/connection.h>

/*extern "C" {
#include <lwip/stats.h>
}*/

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

	void start();

private:
	class Child_starter_thread : Genode::Thread_deprecated<2*4096>
	{
	public:
		Child_starter_thread();
		void do_start(int _target_socket);
		void do_stop(int _target_socket);
		void do_clear(int _target_socket);
		void do_send_descs(int _target_socket);
		void do_send_binaries(int _target_socket);
		ssize_t thread_receive_data(void* data, size_t size, int _target_socket);

	private:
		Timer::Connection _timer;
		Taskloader_connection _task_loader;
		void entry() override;
	};

	int _listen_socket;
	struct sockaddr_in _in_addr;
	sockaddr _target_addr;
	Taskloader_connection _task_loader;
	Parser_connection _parser;
	Timer::Connection timer;
	static Child_starter_thread _starter_thread;
};
