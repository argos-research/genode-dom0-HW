#include "dom0_server.h"

#include <cstring>
#include <vector>
#include <string>

#include <base/printf.h>
#include <lwip/genode.h>
#include <os/attached_ram_dataspace.h>
#include <nic/packet_allocator.h>

#include "communication_magic_numbers.h"
#include <timer_session/connection.h>
#include <os/config.h>

/* Rtcr includes */
#include "rtcr/target_child.h"
#include "rtcr/target_state.h"
#include "rtcr/checkpointer.h"
#include "rtcr/restorer.h"

#include "target_state.pb.h"

Dom0_server::Dom0_server(Genode::Env &env) :
	_listen_socket(0),
	_in_addr{0},
	_target_addr{0},
	_task_loader{},
	_parser{},
	_env{env},
	_rtcr{env}
{
	lwip_tcpip_init();

	enum { BUF_SIZE = Nic::Packet_allocator::DEFAULT_PACKET_SIZE * 128 };

	Genode::Xml_node network = Genode::config()->xml_node().sub_node("network");

	_in_addr.sin_family = AF_INET;
	
	if (network.attribute_value<bool>("dhcp", true))
	{
		
		PDBG("DHCP network...");
		if (lwip_nic_init(0,
		                  0,
		                  0,
		                  BUF_SIZE,
		                  BUF_SIZE)) {
			PERR("lwip init failed!");
			return;
		}
		/* dhcp assignement takes some time... */
		PDBG("Waiting 10s for ip assignement");
		Timer::Connection timer;
		timer.msleep(10000);
		_in_addr.sin_addr.s_addr = INADDR_ANY;
	}
	else
	{
		PDBG("manual network...");
		char ip_addr[16] = {0};
		char subnet[16] = {0};
		char gateway[16] = {0};
		char port[5] = {0};

		network.attribute("ip-address").value(ip_addr, sizeof(ip_addr));
		network.attribute("subnet-mask").value(subnet, sizeof(subnet));
		network.attribute("default-gateway").value(gateway, sizeof(gateway));
		network.attribute("port").value(port, sizeof(port));

		_in_addr.sin_port = htons(atoi(port));

		if (lwip_nic_init(inet_addr(ip_addr),
		                  inet_addr(subnet),
		                  inet_addr(gateway),
		                  BUF_SIZE,
		                  BUF_SIZE)) {
			PERR("lwip init failed!");
			return;
		}
		_in_addr.sin_addr.s_addr = inet_addr(ip_addr);
	}

	if ((_listen_socket = lwip_socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		PERR("No socket available!");
		return;
	}
	if (lwip_bind(_listen_socket, (struct sockaddr*)&_in_addr, sizeof(_in_addr)))
	{
		PERR("Bind failed!");
		return;
	}
	if (lwip_listen(_listen_socket, 5))
	{
		PERR("Listen failed!");
		return;
	}
	PINF("Listening...\n");
}

Dom0_server::~Dom0_server()
{
	disconnect();
}

int Dom0_server::connect()
{
	socklen_t len = sizeof(_target_addr);
	_target_socket = lwip_accept(_listen_socket, &_target_addr, &len);
	if (_target_socket < 0)
	{
		PWRN("Invalid socket from accept!");
		return _target_socket;
	}
	sockaddr_in* target_in_addr = (sockaddr_in*)&_target_addr;
	PINF("Got connection from %s", inet_ntoa(target_in_addr));
	return _target_socket;
}

void Dom0_server::serve()
{
	int message = 0;
	while (true)
	{
		NETCHECK_LOOP(receiveInt32_t(message));
		if (message == CHECKPOINT)
		{
			Timer::Connection timer { _env };
			Genode::Heap              heap            { _env.ram(), _env.rm() };
			Genode::Service_registry  parent_services { };
			Rtcr::Target_child child { _env, heap, parent_services, "sheep_counter", 0 };
			child.start();

			timer.msleep(3000);
		
			Rtcr::Target_state ts(_env, heap);
			protobuf::Target_state _ts;
			/* PD Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_pd_session_info> _stored_pd_sessions 			= ts._stored_pd_sessions;
			Rtcr::Stored_pd_session_info pd_session 					= *_stored_pd_sessions.first();
			Genode::List<Rtcr::Stored_signal_context_info> stored_context_infos 		= pd_session.stored_context_infos;
			//Genode::List<Rtcr::Stored_signal_source_info> stored_source_infos 		= pd_session.stored_source_infos;
			Genode::List<Rtcr::Stored_native_capability_info> stored_native_cap_infos 	= pd_session.stored_native_cap_infos;
			Rtcr::Stored_signal_context_info context 					= *stored_context_infos.first();
			//Rtcr::Stored_signal_source_info source 					= *stored_source_infos.first();
			Rtcr::Stored_native_capability_info native_capability 				= *stored_native_cap_infos.first();
			Genode::uint16_t signal_source_badge 						= context.signal_source_badge;
			unsigned long imprint 								= context.imprint;
			Genode::uint16_t ep_badge 							= native_capability.ep_badge;
			/* protobuf */
			protobuf::Stored_pd_session_info _pd 						= _ts._stored_pd_sessions(0);
			protobuf::Stored_signal_context_info _context					= _pd.stored_context_infos(0);
			//protobuf::Stored_signal_source_info _source 					= _pd.stored_source_infos(0);
			protobuf::Stored_native_capability_info _native_capability 			= _pd.stored_native_cap_infos(0);
			_context.set_signal_source_badge(signal_source_badge);
			_context.set_imprint(imprint);
			_native_capability.set_signal_source_badge(ep_badge);
			
			/* CPU Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_cpu_session_info> _stored_cpu_sessions 		= ts._stored_cpu_sessions;
			Rtcr::Stored_cpu_session_info cpu_session 					= *_stored_cpu_sessions.first();
			Genode::uint16_t cpu_session_sigh_badge						= cpu_session.sigh_badge;
			Genode::List<Rtcr::Stored_cpu_thread_info> stored_cpu_thread_infos		= cpu_session.stored_cpu_thread_infos;
			Rtcr::Stored_cpu_thread_info cpu_thread						= *stored_cpu_thread_infos.first();
			Genode::uint16_t pd_session_badge						= cpu_thread.pd_session_badge;
			Genode::Cpu_session::Name name							= cpu_thread.name;
			Genode::Cpu_session::Weight weight						= cpu_thread.weight;
			Genode::addr_t utcb								= cpu_thread.utcb;
			bool started									= cpu_thread.started;
			bool paused									= cpu_thread.paused;
			bool single_step								= cpu_thread.single_step;
			Genode::Affinity::Location affinity						= cpu_thread.affinity;
			Genode::uint16_t cpu_thread_sigh_badge						= cpu_thread.sigh_badge;
			Genode::Thread_state target_state						= cpu_thread.ts;
			/* protobuf */
			protobuf::Stored_cpu_session_info _cpu_session 					= _ts._stored_cpu_sessions(0);
			protobuf::Stored_cpu_thread_info _cpu_thread 					= _cpu_session.stored_cpu_thread_infos(0);
			_cpu_session.set_sigh_badge(cpu_session_sigh_badge);
			_cpu_thread.set_pd_session_badge(pd_session_badge);
			_cpu_thread.set_name(name.string());
			_cpu_thread.set_weight(std::to_string(weight.value).c_str());
			_cpu_thread.set_utcb(utcb);
			_cpu_thread.set_started(started);
			_cpu_thread.set_paused(paused);
			_cpu_thread.set_single_step(single_step);
			_cpu_thread.set_affinity(affinity.xpos());
			_cpu_thread.set_sigh_badge(cpu_thread_sigh_badge);
			_cpu_thread.set_ts(target_state.exception);

			/* RAM Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_ram_session_info> _stored_ram_sessions 		= ts._stored_ram_sessions;
			Rtcr::Stored_ram_session_info ram_session					= *_stored_ram_sessions.first();
			Genode::List<Rtcr::Stored_ram_dataspace_info> stored_ramds_infos		= ram_session.stored_ramds_infos;
			Rtcr::Stored_ram_dataspace_info ramds						= *stored_ramds_infos.first();
			Genode::Ram_dataspace_capability memory_content					= ramds.memory_content;
			Genode::size_t ram_size								= ramds.size;
			Genode::Cache_attribute cached							= ramds.cached;
			bool managed									= ramds.managed;
			Genode::size_t timestamp							= ramds.timestamp;
			/* protobuf */
			protobuf::Stored_ram_session_info _ram_session					= _ts._stored_ram_sessions(0);
			protobuf::Stored_ram_dataspace_info _ramds					= _ram_session.stored_ramds_infos(0);
			_ramds.set_size(ram_size);
			_ramds.set_cached(cached);
			_ramds.set_managed(managed);
			_ramds.set_timestamp(timestamp);

			/* ROM Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_rom_session_info> _stored_rom_sessions 		= ts._stored_rom_sessions;
			Rtcr::Stored_rom_session_info rom_session					= *_stored_rom_sessions.first();
			Genode::uint16_t dataspace_badge						= rom_session.dataspace_badge;
			Genode::uint16_t rom_sigh_badge							= rom_session.sigh_badge;
			/* protobuf */
			protobuf::Stored_rom_session_info _rom_session					= _ts._stored_rom_sessions(0);
			_rom_session.set_dataspace_badge(dataspace_badge);
			_rom_session.set_sigh_badge(rom_sigh_badge);

			/* RM Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_rm_session_info> _stored_rm_sessions 			= ts._stored_rm_sessions;
			Rtcr::Stored_rm_session_info rm_session						= *_stored_rm_sessions.first();
			Genode::List<Rtcr::Stored_region_map_info> _stored_region_map_infos		= rm_session.stored_region_map_infos;
			Rtcr::Stored_region_map_info region_map						= *_stored_region_map_infos.first();
			Genode::size_t   rm_size							= region_map.size;
			Genode::uint16_t ds_badge							= region_map.ds_badge;
			Genode::uint16_t rm_sigh_badge							= region_map.sigh_badge;
			Genode::List<Rtcr::Stored_attached_region_info> _stored_attached_region_infos	= region_map.stored_attached_region_infos;
			Rtcr::Stored_attached_region_info attached_region				= *_stored_attached_region_infos.first();
			Genode::uint16_t attached_ds_badge						= attached_region.attached_ds_badge;
			//Genode::Ram_dataspace_capability const memory_content;
			Genode::size_t attached_rm_size							= attached_region.size;
			Genode::off_t offset								= attached_region.offset;
			Genode::addr_t rel_addr								= attached_region.rel_addr;
			bool executable									= attached_region.executable;
			/* protobuf */
			protobuf::Stored_rm_session_info _rm_session					= _ts._stored_rm_sessions(0);
			protobuf::Stored_region_map_info _region_map_infos				= _rm_session.stored_region_map_infos(0);
			protobuf::Stored_attached_region_info _attached_region_infos			= _region_map_infos.stored_attached_region_infos(0);
			_region_map_infos.set_size(rm_size);
			_region_map_infos.set_ds_badge(ds_badge);
			_region_map_infos.set_sigh_badge(rm_sigh_badge);
			_attached_region_infos.set_attached_ds_badge(attached_ds_badge);
			_attached_region_infos.set_size(attached_rm_size);
			_attached_region_infos.set_offset(offset);
			_attached_region_infos.set_rel_addr(rel_addr);
			_attached_region_infos.set_executable(executable);
			
			/* LOG Session */
			/* rtcr */
			//Genode::List<Rtcr::Stored_log_session_info> _stored_log_sessions 		= ts._stored_log_sessions;
			/* empty */

			/* Timer Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_timer_session_info> _stored_timer_sessions 		= ts._stored_timer_sessions;
			Rtcr::Stored_timer_session_info timer_session					= *_stored_timer_sessions.first();
			Genode::uint16_t timer_sigh_badge						= timer_session.sigh_badge;
			unsigned         timeout							= timer_session.timeout;
			bool             periodic							= timer_session.periodic;
			/* protobuf */
			protobuf::Stored_timer_session_info _timer_session				= _ts._stored_timer_sessions(0);
			_timer_session.set_sigh_badge(timer_sigh_badge);
			_timer_session.set_timeout(timeout);
			_timer_session.set_periodic(periodic);

			Rtcr::Checkpointer ckpt(heap, child, ts);
			ckpt.checkpoint();

			Rtcr::Target_child child_restored { _env, heap, parent_services, "sheep_counter", 0 };
			Rtcr::Restorer resto(heap, child_restored, ts);
			child_restored.start(resto);
		}
		else if (message == SEND_DESCS)
		{
			PDBG("Ready to receive descs\n");
			std::string foo="1";
                        int32_t size=foo.size();
                        /* Send size of serialized String to SD2 */
                        lwip_write(_target_socket,&size,4);
                        /* Send serialized String to SD2 */
                        lwip_write(_target_socket,(void*)foo.c_str(),foo.size());
			int time_before=timer.elapsed_ms();
			_starter_thread.do_send_descs(_target_socket);
			PDBG("Done SEND_DESCS. Took: %lu",timer.elapsed_ms()-time_before);
		}
		else if (message == CLEAR)
		{
			std::string foo="1";
                        int32_t size=foo.size();
                        /* Send size of serialized String to SD2 */
                        lwip_write(_target_socket,&size,4);
                        /* Send serialized String to SD2 */
                        lwip_write(_target_socket,(void*)foo.c_str(),foo.size());
			int time_before=timer.elapsed_ms();
			_starter_thread.do_clear(_target_socket);
			PDBG("Done CLEAR. Took: %lu",timer.elapsed_ms()-time_before);
		}
		else if (message == SEND_BINARIES)
		{
			int time_before=timer.elapsed_ms();
			_starter_thread.do_send_binaries(_target_socket);
			PDBG("Done SEND_BINARIES. Took: %lu",timer.elapsed_ms()-time_before);
		}
		else if (message == GET_LIVE)
		{
			int time_before=timer.elapsed_ms();
			//stats_proto stats = {};
			//char *name="dom0";
			//stats_display();
			//stats_display_proto(&stats, name);
			Genode::Dataspace_capability xmlDsCap = _parser.live_data();
			Genode::Region_map* rm = Genode::env()->rm_session();
			char* xml = (char*)rm->attach(xmlDsCap);

			size_t size = std::strlen(xml) + 1;
			//PINF("Sending profile data of size %d", size);
			NETCHECK_LOOP(sendInt32_t(size));
			NETCHECK_LOOP(send_data(xml, size));

			rm->detach(xml);
			PDBG("Done GET_LIVE. Took: %lu",timer.elapsed_ms()-time_before);
		}
		else if (message == START)
		{
			std::string foo="1";
        		int32_t size=foo.size();
        		/* Send size of serialized String to SD2 */
        		lwip_write(_target_socket,&size,4);
        		/* Send serialized String to SD2 */
        		lwip_write(_target_socket,(void*)foo.c_str(),foo.size());
			int time_before=timer.elapsed_ms();
			_starter_thread.do_start(_target_socket);
			PDBG("Done START. Took: %lu",timer.elapsed_ms()-time_before);
		}
		else if (message == STOP)
		{
			std::string foo="1";
                        int32_t size=foo.size();
                        /* Send size of serialized String to SD2 */
                        lwip_write(_target_socket,&size,4);
                        /* Send serialized String to SD2 */
                        lwip_write(_target_socket,(void*)foo.c_str(),foo.size());
			int time_before=timer.elapsed_ms();
			_starter_thread.do_stop(_target_socket);
			PDBG("Done STOP. Took: %lu",timer.elapsed_ms()-time_before);
		}
		else if (message == GET_PROFILE)
		{
			int time_before=timer.elapsed_ms();
			_starter_thread.do_send_profile(_target_socket);
			PDBG("Done GET_PROFILE. Took: %lu",timer.elapsed_ms()-time_before);
		}
		else
		{
			//PWRN("Unknown message: %d", message);
		}
	}
}

void Dom0_server::disconnect()
{
	lwip_close(_target_socket);
	PERR("Target socket closed.");
	lwip_close(_listen_socket);
	PERR("Server socket closed.");
}

Dom0_server::Child_starter_thread::Child_starter_thread() :
	Thread_deprecated{"child_starter"}
{
	start();
}

void Dom0_server::Child_starter_thread::do_start(int target_socket)
{
	PDBG("Starting tasks.");
	_task_loader.start();
}

void Dom0_server::Child_starter_thread::do_stop(int target_socket)
{
	PDBG("Stopping tasks.");
	_task_loader.stop();
}

void Dom0_server::Child_starter_thread::do_clear(int target_socket)
{
	PDBG("Clearing tasks.");
	_task_loader.clear_tasks();
}

void Dom0_server::Child_starter_thread::do_send_descs(int target_socket)
{
	PDBG("Ready to receive task description.");

	// Get XML size.
	int xml_size;
	lwip_read(target_socket, &xml_size, ntohl(4));
	Genode::Attached_ram_dataspace xml_ds(Genode::env()->ram_session(), xml_size);
	PINF("Ready to receive XML of size %d.", xml_size);

	// Get XML file.
	thread_receive_data(xml_ds.local_addr<char>(), xml_size,target_socket);
	PDBG("Received XML. Initializing tasks.");
	_task_loader.add_tasks(xml_ds.cap());
}

void Dom0_server::Child_starter_thread::do_send_binaries(int target_socket)
{
	PDBG("Ready to receive binaries.");

	// Get number of binaries to receive.
	int num_binaries = 0;
	lwip_read(target_socket, &num_binaries, ntohl(4));
	PINF("%d binar%s to be sent.", num_binaries, num_binaries == 1 ? "y" : "ies");

	// Receive binaries.
	for (int i = 0; i < num_binaries; i++)
	{
		// Client is waiting for ready signal.
		int32_t message=GO_SEND;
		lwip_write(target_socket,&message,4);
		// Get binary name.
		Genode::Attached_ram_dataspace name_ds(Genode::env()->ram_session(), 16);
		thread_receive_data(name_ds.local_addr<char>(), 16, target_socket);
		// Get binary size.
		int32_t binary_size = 0;
		lwip_read(target_socket, &binary_size, ntohl(4));
		// Get binary data.
		Genode::Dataspace_capability binDsCap = _task_loader.binary_ds(name_ds.cap(), binary_size);
		Genode::Region_map* rm = Genode::env()->rm_session();
		char* bin = (char*)rm->attach(binDsCap);
		thread_receive_data(bin, binary_size, target_socket);
		PINF("Got binary '%s' of size %d.", name_ds.local_addr<char>(), binary_size);
		rm->detach(bin);
	}
}

void Dom0_server::Child_starter_thread::do_send_profile(int target_socket)
{
	Genode::Dataspace_capability xmlDsCap = _task_loader.profile_data();
	Genode::Region_map* rm = Genode::env()->rm_session();
	char* xml = (char*)rm->attach(xmlDsCap);
	size_t size = std::strlen(xml) + 1;
	PINF("Sending profile data of size %d", size);
	lwip_write(target_socket,&size,4);
	lwip_write(target_socket,xml,size);
	rm->detach(xml);
}

// Receive data from the socket and write it into data.
ssize_t Dom0_server::Child_starter_thread::thread_receive_data(void* data, size_t size, int _target_socket)
{
	ssize_t result = 0;
	ssize_t position = 0;
	// Because read() might actually read less than size bytes
	// before it returns, we call it in a loop
	// until size bytes have been read.
	do
	{
		result = lwip_read(_target_socket, (char*) data + position, size - position);
		if (result < 1)
		{
			return -errno;
		}
		position += result;

	} while ((size_t) position < size);

	return position;
}

void Dom0_server::Child_starter_thread::entry()
{
	while (true)
	{
	}
}

Dom0_server::Child_starter_thread Dom0_server::_starter_thread;
