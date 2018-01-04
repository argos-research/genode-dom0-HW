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
			Rtcr::Checkpointer ckpt(heap, child, ts);
			ckpt.checkpoint();
			protobuf::Target_state _ts;
			/* PD Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_pd_session_info> _stored_pd_sessions 			= ts._stored_pd_sessions;
			Rtcr::Stored_pd_session_info pd_session 					= *_stored_pd_sessions.first();
			Genode::String<160> pd_creation_args						= pd_session.creation_args;
        		Genode::String<160> pd_upgrade_args						= pd_session.upgrade_args;
			Genode::addr_t   pd_kcap							= pd_session.kcap;
        		Genode::uint16_t pd_badge							= pd_session.badge;
        		bool             pd_bootstrapped						= pd_session.bootstrapped;
			Genode::List<Rtcr::Stored_signal_context_info> stored_context_infos 		= pd_session.stored_context_infos;
			Genode::List<Rtcr::Stored_signal_source_info> stored_source_infos 		= pd_session.stored_source_infos;
			Genode::List<Rtcr::Stored_native_capability_info> stored_native_cap_infos 	= pd_session.stored_native_cap_infos;
			Rtcr::Stored_signal_context_info context 					= *stored_context_infos.first();
			Rtcr::Stored_signal_source_info source 						= *stored_source_infos.first();
			Rtcr::Stored_native_capability_info native_capability 				= *stored_native_cap_infos.first();
			Genode::uint16_t signal_source_badge 						= context.signal_source_badge;
			unsigned long imprint 								= context.imprint;
			Genode::uint16_t ep_badge 							= native_capability.ep_badge;
			/* protobuf */
			protobuf::Stored_pd_session_info _pd 						= _ts._stored_pd_sessions(0);
			protobuf::Stored_signal_context_info _context					= _pd.stored_context_infos(0);
			protobuf::Stored_signal_source_info _source 					= _pd.stored_source_infos(0);
			protobuf::Stored_native_capability_info _native_capability 			= _pd.stored_native_cap_infos(0);
			protobuf::Session_info _pd_session_info						= _pd.session_info();
			protobuf::Stored_general_info _pd_general_info					= _pd_session_info.general_info();
			_context.set_signal_source_badge(signal_source_badge);
			_context.set_imprint(imprint);
			_native_capability.set_signal_source_badge(ep_badge);
			_pd_session_info.set_creation_args(pd_creation_args.string());
			_pd_session_info.set_upgrade_args(pd_upgrade_args.string());
			_pd_general_info.set_kcap(pd_kcap);
			_pd_general_info.set_badge(pd_badge);
			_pd_general_info.set_bootstrapped(pd_bootstrapped);
			
			/* CPU Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_cpu_session_info> _stored_cpu_sessions 		= ts._stored_cpu_sessions;
			Rtcr::Stored_cpu_session_info cpu_session 					= *_stored_cpu_sessions.first();
			Genode::uint16_t cpu_session_sigh_badge						= cpu_session.sigh_badge;
			Genode::String<160> cpu_creation_args                                            = cpu_session.creation_args;
                        Genode::String<160> cpu_upgrade_args                                             = cpu_session.upgrade_args;
                        Genode::addr_t   cpu_kcap                                                        = cpu_session.kcap;
                        Genode::uint16_t cpu_badge                                                       = cpu_session.badge;
                        bool             cpu_bootstrapped                                                = cpu_session.bootstrapped;
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
			Genode::String<160> ram_creation_args                                            = ram_session.creation_args;
                        Genode::String<160> ram_upgrade_args                                             = ram_session.upgrade_args;
                        Genode::addr_t   ram_kcap                                                        = ram_session.kcap;
                        Genode::uint16_t ram_badge                                                       = ram_session.badge;
                        bool             ram_bootstrapped                                                = ram_session.bootstrapped;
			Genode::List<Rtcr::Stored_ram_dataspace_info> stored_ramds_infos		= ram_session.stored_ramds_infos;
			Rtcr::Stored_ram_dataspace_info ramds						= *stored_ramds_infos.first();
			Genode::Ram_dataspace_capability ram_memory_content				= ramds.memory_content;

			/* attache capability to send it over network */
			char* ram_content								= (char*)Genode::env()->rm_session()->attach(ram_memory_content);
			Genode::size_t ram_size								= ramds.size;
			lwip_write(_target_socket,ram_content,ram_size);

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
			Genode::String<160> rom_creation_args                                            = rom_session.creation_args;
                        Genode::String<160> rom_upgrade_args                                             = rom_session.upgrade_args;
                        Genode::addr_t   rom_kcap                                                        = rom_session.kcap;
                        Genode::uint16_t rom_badge                                                       = rom_session.badge;
                        bool             rom_bootstrapped                                                = rom_session.bootstrapped;
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
			Genode::String<160> rm_creation_args                                            = rm_session.creation_args;
                        Genode::String<160> rm_upgrade_args                                             = rm_session.upgrade_args;
                        Genode::addr_t   rm_kcap                                                        = rm_session.kcap;
                        Genode::uint16_t rm_badge                                                       = rm_session.badge;
                        bool             rm_bootstrapped                                                = rm_session.bootstrapped;
			Genode::List<Rtcr::Stored_region_map_info> _stored_region_map_infos		= rm_session.stored_region_map_infos;
			Rtcr::Stored_region_map_info region_map						= *_stored_region_map_infos.first();
			Genode::size_t   rm_size							= region_map.size;
			Genode::uint16_t ds_badge							= region_map.ds_badge;
			Genode::uint16_t rm_sigh_badge							= region_map.sigh_badge;
			Genode::List<Rtcr::Stored_attached_region_info> _stored_attached_region_infos	= region_map.stored_attached_region_infos;
			Rtcr::Stored_attached_region_info attached_region				= *_stored_attached_region_infos.first();
			Genode::uint16_t attached_ds_badge						= attached_region.attached_ds_badge;
			Genode::Ram_dataspace_capability rm_memory_content				= attached_region.memory_content;
			
			/* attache capability to send it over network */
			char* rm_content								= (char*)Genode::env()->rm_session()->attach(rm_memory_content);
			Genode::size_t attached_rm_size							= attached_region.size;
        		lwip_write(_target_socket,&attached_rm_size,4);
			lwip_write(_target_socket,rm_content,attached_rm_size);
			
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
			Genode::String<160> timer_creation_args                                            = timer_session.creation_args;
                        Genode::String<160> timer_upgrade_args                                             = timer_session.upgrade_args;
                        Genode::addr_t   timer_kcap                                                        = timer_session.kcap;
                        Genode::uint16_t timer_badge                                                       = timer_session.badge;
                        bool             timer_bootstrapped                                                = timer_session.bootstrapped;
			Genode::uint16_t timer_sigh_badge						= timer_session.sigh_badge;
			unsigned         timeout							= timer_session.timeout;
			bool             periodic							= timer_session.periodic;
			/* protobuf */
			protobuf::Stored_timer_session_info _timer_session				= _ts._stored_timer_sessions(0);
			_timer_session.set_sigh_badge(timer_sigh_badge);
			_timer_session.set_timeout(timeout);
			_timer_session.set_periodic(periodic);
		}
		else if (message == RESTORE)
		{
			Genode::Heap              heap            { _env.ram(), _env.rm() };
			Genode::Service_registry  parent_services { };
			Rtcr::Target_state ts(_env, heap);
			protobuf::Target_state _ts;
	
			/* PD Session *
			/* protobuf */
			protobuf::Stored_pd_session_info _pd 						= _ts._stored_pd_sessions(0);
			protobuf::Stored_session_info __pd_session_info					= _pd.session_info();
			protobuf::Stored_general_info __pd_general_info					= __pd_session_info.general_info();
			protobuf::Stored_signal_context_info _context					= _pd.stored_context_infos(0);
			protobuf::Stored_signal_source_info _source 					= _pd.stored_source_infos(0);
			protobuf::Stored_native_capability_info _native_capability 			= _pd.stored_native_cap_infos(0);
			/* TODO object needed */
			const char* __pd_creation_args							= __pd_session_info.creation_args().c_str();
                        const char* __pd_upgrade_args							= __pd_session_info.upgrade_args().c_str();
                        Genode::addr_t __pd_kcap								= __pd_general_info.kcap();
                        Genode::uint16_t __pd_local_name							= __pd_general_info.badge();
                        bool __pd_bootstrapped								= __pd_general_info.bootstrapped();
			protobuf::Stored_region_map_info __pd_stored_address_space			= _pd.stored_address_space();
			protobuf::Stored_normal_info __pd_stored_address__normal_info				= __pd_stored_address_space.normal_info();
			protobuf::Stored_general_info __pd_stored_address_general_info				= __pd_stored_address_normal_info.general_info();
			Genode::addr_t __pd_stored_address_space_kcap					= __pd_stored_address_general_info.kcap();
                        Genode::uint16_t __pd_stored_address_space_local_name				= __pd_stored_address_general_info.local_name();
                        bool __pd_stored_address_space_bootstrapped					= __pd_stored_address_general_info.bootstrapped();
                        Genode::size_t __pd_stored_address_space_size					= __pd_stored_address_general_info.space_size();
                        Genode::uint16_t __pd_stored_address_space_ds_badge				= __pd_stored_address_space.ds_badge();
                        Genode::uint16_t __pd_stored_address_space_sigh_badge				= __pd_stored_address_space.sigh_badge();
        		protobuf::Stored_region_map_info __pd_stored_stack_area				= _pd.stored_stack_area();
			protobuf::Stored_normal_info __pd_stored_stack_normal_info                            = __pd_stored_stack_area.normal_info();
                        protobuf::Stored_general_info __pd_stored_stack_general_info                          = __pd_stored_stack_normal_info.general_info();
                        Genode::addr_t __pd_stored_stack_kcap                                   = __pd_stored_stack_general_info.kcap();
                        Genode::uint16_t __pd_stored_stack_local_name                           = __pd_stored_stack_general_info.local_name();
                        bool __pd_stored_stack_bootstrapped                                     = __pd_stored_stack_general_info.bootstrapped();
                        Genode::size_t __pd_stored_stack_size                                   = __pd_stored_stack_general_info.space_size();
                        Genode::uint16_t __pd_stored_stack_area_ds_badge                             = __pd_stored_stack_area.ds_badge();
                        Genode::uint16_t __pd_stored_stack_area_sigh_badge                           = __pd_stored_stack_area.sigh_badge();
        		protobuf::Stored_region_map_info __pd_stored_linker_area			= _pd.stored_linker_area();
			protobuf::Stored_normal_info __pd_stored_linker_normal_info                            = __pd_stored_address_space.normal_info();
                        protobuf::Stored_general_info __pd_stored_linker_general_info                          = __pd_stored_linker_normal_info.general_info();
                        Genode::addr_t __pd_stored_linker_kcap                                   = __pd_stored_linker_general_info.kcap();
                        Genode::uint16_t __pd_stored_linker_local_name                           = __pd_stored_linker_general_info.local_name();
                        bool __pd_stored_linker_bootstrapped                                     = __pd_stored_linker_general_info.bootstrapped();
                        Genode::size_t __pd_stored_linker_size                                   = __pd_stored_linker_general_info.space_size();
                        Genode::uint16_t __pd_stored_linker_area_ds_badge                             = __pd_stored_linker_area.ds_badge();
                        Genode::uint16_t __pd_stored_linker_area_sigh_badge                           = __pd_stored_linker_area.sigh_badge();
			Genode::uint16_t signal_source_badge = _context.signal_source_badge();
			unsigned long imprint = _context.imprint();
			Genode::uint16_t ep_badge = _native_capability.signal_source_badge();
			/* rtcr */
			Rtcr::Stored_region_map_info _pd_stored_address_space				= Rtcr::Stored_region_map_info(__pd_stored_address_space_kcap, __pd_stored_address_space_local_name, __pd_stored_address_space_bootstrapped, __pd_stored_address_space_size, __pd_stored_address_space_ds_badge, __pd_stored_address_space_sigh_badge);
			Rtcr::Stored_region_map_info _pd_stored_stack_area                              = Rtcr::Stored_region_map_info(__pd_stored_stack_kcap, __pd_stored_stack_local_name, __pd_stored_stack_bootstrapped, __pd_stored_stack_size, __pd_stored_stack_area_ds_badge, __pd_stored_stack_area_sigh_badge);
			Rtcr::Stored_region_map_info _pd_stored_linker_area                             = Rtcr::Stored_region_map_info(__pd_stored_linker_kcap, __pd_stored_linker_local_name, __pd_stored_linker_bootstrapped, __pd_stored_linker_size, __pd_stored_linker_area_ds_badge, __pd_stored_linker_area_sigh_badge);
			Genode::List<Rtcr::Stored_pd_session_info> _stored_pd_sessions 			= ts._stored_pd_sessions;
			Rtcr::Stored_pd_session_info pd_session 					= Rtcr::Stored_pd_session_info(__pd_creation_args, __pd_upgrade_args, __pd_kcap, __pd_local_name, __pd_bootstrapped, _pd_stored_address_space, _pd_stored_stack_area, _pd_stored_linker_area);
			Genode::List<Rtcr::Stored_signal_context_info> _stored_context_infos 		= pd_session.stored_context_infos;
			Genode::List<Rtcr::Stored_signal_source_info> _stored_source_infos 		= pd_session.stored_source_infos;
			Genode::List<Rtcr::Stored_native_capability_info> _stored_native_cap_infos 	= pd_session.stored_native_cap_infos;

			/* CPU Session */
                        /* protobuf */
                        protobuf::Stored_cpu_session_info _cpu_session                                  = _ts._stored_cpu_sessions(0);
			protobuf::Stored_session_info __cpu_session_info         			= _cpu.session_info();
                        protobuf::Stored_general_info __cpu_session_general_info                                = __cpu_session_info.general_info();
                        protobuf::Stored_cpu_thread_info _cpu_thread                                    = _cpu_session.stored_cpu_thread_infos(0);
			Genode::uint16_t cpu_session_sigh_badge                                         = _cpu_session.sigh_badge();
			const char* __cpu_creation_args                                                       = __cpu_session_info.creation_args().c_str();
                        const char* __cpu_upgrade_args                                                        = __cpu_session_info.upgrade_args().c_str();
                        Genode::addr_t __cpu_session_kcap                                                             = __cpu_session_general_info.kcap();
                        Genode::uint16_t __cpu_session_local_name                                                     = __cpu_session_general_info.badge();
                        bool __cpu_session_bootstrapped                                                               = __cpu_session_general_info.bootstrapped();
			protobuf::Stored_normal_info __cpu_normal_info					= _cpu_thread.normal_info();
			protobuf::Stored_general_info __cpu_general_info				= __cpu_normal_info.general_info();
			Genode::addr_t __cpu_kcap								= __cpu_general_info.kcap();
                        Genode::uint16_t __cpu_local_name							= __cpu_general_info.local_name();
                        bool __cpu_bootstrapped								= __cpu_general_info.bootstrapped();
			Genode::uint16_t pd_session_badge                                               = _cpu_thread.pd_session_badge();
                        //Genode::Cpu_session::Name name                                                  = _cpu_thread.name();
                        Genode::addr_t utcb                                                             = _cpu_thread.utcb();
                        bool started                                                                    = _cpu_thread.started();
                        bool paused                                                                     = _cpu_thread.paused();
                        bool single_step                                                                = _cpu_thread.single_step();
                        Genode::Affinity::Location affinity(_cpu_thread.affinity(),0);
                        Genode::uint16_t cpu_thread_sigh_badge                                          = _cpu_thread.sigh_badge();
			/* rtcr */
                        Genode::List<Rtcr::Stored_cpu_session_info> _stored_cpu_sessions                = ts._stored_cpu_sessions;
			Rtcr::Stored_cpu_session_info cpu_session					= Rtcr::Stored_cpu_session_info(__cpu_creation_args, __cpu_upgrade_args, __cpu_session_kcap, __cpu_session_local_name, __cpu_session_bootstrapped, cpu_session_sigh_badge);
			Genode::List<Rtcr::Stored_cpu_thread_info> stored_cpu_thread_infos              = cpu_session.stored_cpu_thread_infos;
			Rtcr::Stored_cpu_thread_info cpu_thread						= Rtcr::Stored_cpu_thread_info(__cpu_kcap, __cpu_local_name, __cpu_bootstrapped, pd_session_badge, "", Genode::Cpu_session::Weight(), utcb, started, paused, single_step, affinity, cpu_thread_sigh_badge);
			stored_cpu_thread_infos.insert(&cpu_thread);
			_stored_cpu_sessions.insert(&cpu_session);
			
			 /* RAM Session */
                        /* protobuf */
                        protobuf::Stored_ram_session_info _ram_session                                  = _ts._stored_ram_sessions(0);
                        protobuf::Stored_ram_dataspace_info _ramds                                      = _ram_session.stored_ramds_infos(0);
			protobuf::Stored_session_info __ram_session_info                                 = _ram_session.session_info();
                        protobuf::Stored_general_info __ram_general_info                                 = __ram_session_info.general_info();
                        /* TODO object needed */
			const char* __ram_creation_args                                                  = __ram_session_info.creation_args().c_str();
                        const char* __ram_upgrade_args                                                   = __ram_session_info.upgrade_args().c_str();
                        Genode::addr_t __ram_kcap                                                        = __ram_general_info.kcap();
                        Genode::uint16_t __ram_local_name                                                = __ram_general_info.badge();
                        bool __ram_bootstrapped                                                          = __ram_general_info.bootstrapped();
			Genode::size_t ram_size                                                         = _ramds.size();
			Genode::Ram_dataspace_capability _ram_memory_content                            = Genode::env()->ram_session()->alloc(ram_size);
			char* _ram_content								= (char*)Genode::env()->rm_session()->attach(_ram_memory_content);
			lwip_read(_target_socket, _ram_content ,ntohl(ram_size));			
                        //Genode::Cache_attribute cached                                                  = _ramds.cached();
                        bool managed                                                                    = _ramds.managed();
                        Genode::size_t timestamp							= _ramds.timestamp();
			/* rtcr */
                        Genode::List<Rtcr::Stored_ram_session_info> _stored_ram_sessions                = ts._stored_ram_sessions;
                        Rtcr::Stored_ram_session_info ram_session                                       = Rtcr::Stored_ram_session_info(__ram_creation_args, __ram_upgrade_args, __ram_kcap, __ram_local_name, __ram_bootstrapped);
                        Genode::List<Rtcr::Stored_ram_dataspace_info> stored_ramds_infos                = ram_session.stored_ramds_infos;
                        Rtcr::Stored_ram_dataspace_info ramds                                           = Rtcr::Stored_ram_dataspace_info(_memory_content, ram_size, false, managed, timestamp);

                        /* ROM Session */
                        /* protobuf */
                        protobuf::Stored_rom_session_info _rom_session                                  = _ts._stored_rom_sessions(0);
			protobuf::Stored_session_info __rom_session_info                                 = _rom_session.session_info();
                        protobuf::Stored_general_info __rom_general_info                                 = __rom_session_info.general_info();
			const char* __rom_creation_args                                                  = __rom_session_info.creation_args().c_str();
                        const char* __rom_upgrade_args                                                   = __rom_session_info.upgrade_args().c_str();
                        Genode::addr_t __rom_kcap                                                        = __rom_general_info.kcap();
                        Genode::uint16_t __rom_local_name                                                = __rom_general_info.badge();
                        bool __rom_bootstrapped                                                          = __rom_general_info.bootstrapped();
                        Genode::uint16_t dataspace_badge                                                = _rom_session.dataspace_badge();
                        Genode::uint16_t rom_sigh_badge                                                 = _rom_session.sigh_badge();
			/* rtcr */
                        Genode::List<Rtcr::Stored_rom_session_info> _stored_rom_sessions                = ts._stored_rom_sessions;
                        Rtcr::Stored_rom_session_info rom_session                                       = Rtcr::Stored_rom_session_info(__rom_creation_args, __rom_upgrade_args, __rom_kcap, __rom_local_name, __rom_bootstrapped ,dataspace_badge, rom_sigh_badge);

                        /* RM Session */
                        /* protobuf */
                        protobuf::Stored_rm_session_info _rm_session                                    = _ts._stored_rm_sessions(0);
                        protobuf::Stored_region_map_info _region_map                              	= _rm_session.stored_region_map_infos(0);
			protobuf::Stored_session_info __rm_session_info                                 = _rm_session.session_info();
                        protobuf::Stored_general_info __rm_general_info                                 = __rm_session_info.general_info();
			/* TODO object needed */
			const char* __rm_creation_args                                                  = __rm_session_info.creation_args().c_str();
                        const char* __rm_upgrade_args                                                   = __rm_session_info.upgrade_args().c_str();
                        Genode::addr_t __rm_kcap                                                        = __rm_general_info.kcap();
                        Genode::uint16_t __rm_local_name                                                = __rm_general_info.badge();
                        bool __rm_bootstrapped                                                          = __rm_general_info.bootstrapped();
			Genode::size_t   rm_size                                                        = _region_map.size();
                        Genode::uint16_t ds_badge                                                       = _region_map.ds_badge();
                        Genode::uint16_t rm_sigh_badge                                                  = _region_map.sigh_badge();
                        protobuf::Stored_attached_region_info _attached_region                    	= _region_map.stored_attached_region_infos(0);
                        Genode::uint16_t attached_ds_badge                                              = _attached_region.attached_ds_badge();
                        Genode::size_t attached_rm_size                                                 = _attached_region.size();
			Genode::Ram_dataspace_capability _rm_memory_content                             = Genode::env()->ram_session()->alloc(attached_rm_size);
			char* _rm_content								= (char*)Genode::env()->rm_session()->attach(_rm_memory_content);
			lwip_read(_target_socket, _rm_content ,ntohl(attached_rm_size));
                        
                        Genode::off_t offset                                                            = _attached_region.offset();
                        Genode::addr_t rel_addr                                                         = _attached_region.rel_addr();
                        bool executable                                                                 = _attached_region.executable();
                        /* rtcr */
                        Genode::List<Rtcr::Stored_rm_session_info> _stored_rm_sessions                  = ts._stored_rm_sessions;
                        Rtcr::Stored_rm_session_info rm_session                                         = Rtcr::Stored_rm_session_info(__rm_creation_args, __rm_upgrade_args, __rm_kcap, __rm_local_name, __rm_bootstrapped);
                        Genode::List<Rtcr::Stored_region_map_info> _stored_region_map_infos             = rm_session.stored_region_map_infos;
                        Rtcr::Stored_region_map_info region_map                                         = Rtcr::Stored_region_map_info(rm_size, ds_badge, rm_sigh_badge, stored_attached_region_infos);
                        Genode::List<Rtcr::Stored_attached_region_info> _stored_attached_region_infos   = region_map.stored_attached_region_infos;
                        Rtcr::Stored_attached_region_info attached_region                               = Rtcr::Stored_attached_region_info(attached_ds_badge, _rm_memory_content, rm_size, offset, rel_addr, executable);


                        /* LOG Session */
                        /* rtcr */
                        //Genode::List<Rtcr::Stored_log_session_info> _stored_log_sessions              = ts._stored_log_sessions;
                        /* empty */

                        /* Timer Session */
                        /* protobuf */
                        protobuf::Stored_timer_session_info _timer_session                              = _ts._stored_timer_sessions(0);
			protobuf::Stored_session_info __timer_session_info                                 = _timer_session.session_info();
                        protobuf::Stored_general_info __timer_general_info                                 = __timer_session_info.general_info();
			const char* __timer_creation_args                                                  = __timer_session_info.creation_args().c_str();
                        const char* __timer_upgrade_args                                                   = __timer_session_info.upgrade_args().c_str();
                        Genode::addr_t __timer_kcap                                                        = __timer_general_info.kcap();
                        Genode::uint16_t __timer_local_name                                                = __timer_general_info.badge();
                        bool __timer_bootstrapped                                                          = __timer_general_info.bootstrapped();
			/* TODO object needed */
                        Genode::uint16_t timer_sigh_badge                                               = _timer_session.sigh_badge();
                        unsigned         timeout                                                        = _timer_session.timeout();
                        bool             periodic                                                       = _timer_session.periodic();
			/* rtcr */
                        Genode::List<Rtcr::Stored_timer_session_info> _stored_timer_sessions            = ts._stored_timer_sessions;
                        Rtcr::Stored_timer_session_info timer_session                                   = Rtcr::Stored_timer_session_info(__timer_creation_args, __timer_upgrade_args, __timer_kcap, __timer_local_name, __timer_bootstrapped, timer_sigh_badge, timeout, periodic);


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
