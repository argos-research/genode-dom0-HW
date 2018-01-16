#pragma once

#include <base/heap.h>

//#include "tcp_socket.h"
#include <taskloader/taskloader_connection.h>
#include <parser/parser_connection.h>
#include <timer_session/connection.h>
#include "sched_controller_session/connection.h"

/*extern "C" {
#include <lwip/stats.h>
}*/

#include <util/xml_node.h>

extern "C" {
#include <lwip/sockets.h>
}

#define NETCHECK_LOOP(x)\
	if(x<1)\
	{ \
		PINF("Connection terminated. Waiting for new connection.\n");\
		break;\
	}

// Get XML node attribute if it exists and copy default if not.
bool attribute_value(const Genode::Xml_node& config_node, const char* type, char* dst, const char* default_val, size_t max_len);

namespace Dom0_server{

class Dom0_server// : public Tcp_socket
{
private:
	class Child_starter_thread : Genode::Thread_deprecated<2*4096>
	{
	public:
		Child_starter_thread();
		void do_start(int target_socket);
		void do_stop(int target_socket);
		void do_clear(int target_socket);
		void do_send_descs(int target_socket);
		void do_send_binaries(int target_socket);
		void do_send_profile(int target_socket);
		void do_send_live(int target_socket);
		ssize_t receive_data(void* data, size_t size, int _target_socket);
		ssize_t receiveInt32_t(int32_t& data, int _target_socket);
		ssize_t send_data(void* data, size_t size, int _target_socket);
		ssize_t sendInt32_t(int32_t data, int _target_socket);
		

	private:
		Timer::Connection _timer;
		Taskloader_connection _task_loader;
		Parser_connection _parser;
		void entry() override;
	};

	int _target_socket;
	struct sockaddr_in _target_sockaddr_in;

	int _listen_socket;
	struct sockaddr_in _in_addr;
	sockaddr _target_addr;
	Taskloader_connection _task_loader;
	Parser_connection _parser;
	Timer::Connection timer;
	Sched_controller::Connection _controller;
	static Child_starter_thread _starter_thread;

public:
	Dom0_server();

	~Dom0_server();

	int connect();

	void serve();

	void disconnect();

	void start();

	void send_profile(Genode::String<32> task_name);


};
}
