#pragma once

/* protobuf includes */
#include <target_state.pb.h>

#define timeval timeval_linux

#include "tcp_socket.h"
#include <taskloader/taskloader_connection.h>
#include <parser/parser_connection.h>
#include <timer_session/connection.h>
#include <rtcr_session/connection.h>
#include <base/env.h>
#include <base/component.h>
#include <base/heap.h>
#include <base/service.h>

/* Rtcr includes */
#include "rtcr/target_child.h"
#include "rtcr/target_state.h"
#include "rtcr/checkpointer.h"
#include "rtcr/restorer.h"

/*extern "C" {
#include <lwip/stats.h>
}*/

#include <util/xml_node.h>

// Get XML node attribute if it exists and copy default if not.
bool attribute_value(const Genode::Xml_node& config_node, const char* type, char* dst, const char* default_val, size_t max_len);

class Dom0_server : public Tcp_socket
{
public:
	Dom0_server(Genode::Env &env);

	~Dom0_server();

	void set_session_info(Genode::Heap &heap, Rtcr::Stored_session_info *r, protobuf::Stored_session_info* p);

	void set_normal_info(Genode::Heap &heap, Rtcr::Stored_normal_info *r, protobuf::Stored_normal_info *p);

	void send_ckpt_dataspace(Genode::Ram_dataspace_capability cap, Genode::size_t attached_rm_size, int _target_socket);

	void recv_ckpt_dataspace(Genode::Ram_dataspace_capability cap, Genode::size_t attached_rm_size, int _target_socket);

	int connect();

	void serve();

	void disconnect();

	void start();

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
		ssize_t thread_receive_data(void* data, size_t size, int _target_socket);

	private:
		Timer::Connection _timer;
		Taskloader_connection _task_loader;
		void entry() override;
	};

	Genode::Env &_env;
	int _listen_socket;
	struct sockaddr_in _in_addr;
	sockaddr _target_addr;
	Taskloader_connection _task_loader;
	Parser_connection _parser;
	Timer::Connection timer;
	Rtcr::Connection _rtcr;
	static Child_starter_thread _starter_thread;
};
