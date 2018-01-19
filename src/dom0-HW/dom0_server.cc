
#include "dom0_server.h"
#include <base/sleep.h>
/* etc */
#include <cstdio>
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

void Dom0_server::set_session_info(Genode::Heap &heap, Rtcr::Stored_session_info *r, protobuf::Stored_session_info *p)
{
	Genode::String<160> creation_args               = r->creation_args;
        Genode::String<160> upgrade_args                = r->upgrade_args;
        Genode::addr_t   kcap                           = r->kcap;
        Genode::uint16_t badge                          = r->badge;
        bool             bootstrapped                   = r->bootstrapped;

	protobuf::Stored_general_info* general		= new (heap) protobuf::Stored_general_info();

	general->set_kcap(kcap);
        general->set_badge(badge);
        general->set_bootstrapped(bootstrapped);

	p->set_allocated_general_info(general);
        p->set_creation_args(creation_args.string());
        p->set_upgrade_args(upgrade_args.string());
}

void Dom0_server::set_normal_info(Genode::Heap &heap, Rtcr::Stored_normal_info *r, protobuf::Stored_normal_info *p)
{
	Genode::addr_t   kcap                           = r->kcap;
        Genode::uint16_t badge                          = r->badge;
        bool             bootstrapped                   = r->bootstrapped;

	protobuf::Stored_general_info* general		= new (heap) protobuf::Stored_general_info();

	general->set_kcap(kcap);
        general->set_badge(badge);
        general->set_bootstrapped(bootstrapped);

	p->set_allocated_general_info(general);
}

void Dom0_server::send_ckpt_dataspace(Genode::Ram_dataspace_capability cap, Genode::size_t attached_rm_size, int _target_socket)
{
	if(268435456>attached_rm_size)
	{
        	char* rm_content                         	= (char*)_env.rm().attach(cap);
        	lwip_write(_target_socket,&attached_rm_size,4);
        	lwip_write(_target_socket,rm_content,attached_rm_size);
        	Genode::env()->rm_session()->detach(rm_content);
	}
}

void Dom0_server::recv_ckpt_dataspace(Genode::Ram_dataspace_capability cap, Genode::size_t attached_rm_size, int _target_socket)
{
	if(268435456>attached_rm_size)
	{
		Genode::size_t size=0;
        	char* rm_content                         	= (char*)_env.rm().attach(cap);
        	lwip_read(_target_socket, &size ,4);
		size=ntohl(size);
		PDBG("Receiving file of size %d, expected size %d", size, attached_rm_size);
		_starter_thread.thread_receive_data(rm_content,size,_target_socket);        	
        	Genode::env()->rm_session()->detach(rm_content);
	}
}

void Dom0_server::serve()
{
	int message = 0;
	while (true)
	{
		NETCHECK_LOOP(receiveInt32_t(message));
		if (message == CHECKPOINT)
		{
			//char *bar;
			Timer::Connection timer { _env };
			Genode::Heap              heap            { _env.ram(), _env.rm()};
			//bar=_env.rm().attach(_env.pd().address_space().dataspace());
			//PDBG("Address Space Address: %p", bar);
			Genode::Service_registry  parent_services { };
			Rtcr::Target_child child { _env, heap, parent_services, "sheep_counter", 0 };
			child.start();

			timer.msleep(3000);
		
			Rtcr::Target_state ts(_env, heap);
			Rtcr::Checkpointer ckpt(heap, child, ts);
			ckpt.checkpoint();
			
			/*
			Rtcr::Target_child child_restored { _env, heap, parent_services, "sheep_counter", 0 };
			Rtcr::Restorer resto(heap, child_restored, ts);
                        child_restored.start(resto);
			Genode::sleep_forever();
			*/

			protobuf::Target_state _ts = protobuf::Target_state();

			_ts.set__cap_idx_alloc_addr(ts._cap_idx_alloc_addr);

			/* PD Session */
			Genode::List<Rtcr::Stored_pd_session_info> _stored_pd_sessions 			= ts._stored_pd_sessions;
			Rtcr::Stored_pd_session_info* pd_session 					= _stored_pd_sessions.first();

			while(pd_session) {
				protobuf::Stored_pd_session_info* _pd                                           = _ts.add__stored_pd_sessions();
                        	protobuf::Stored_session_info* _pd_session                                  	= new (heap) protobuf::Stored_session_info();
			
				set_session_info(heap, pd_session, _pd_session);
                        
				_pd->set_allocated_session_info(_pd_session);

				Rtcr::Stored_region_map_info *stored_address_space				= &pd_session->stored_address_space;
				Genode::size_t   stored_address_space_size					= stored_address_space->size;
				Genode::uint16_t stored_address_space_ds_badge					= stored_address_space->ds_badge;
				Genode::uint16_t stored_address_space_sigh_badge				= stored_address_space->sigh_badge;

				protobuf::Stored_region_map_info* _stored_address_space				= new (heap) protobuf::Stored_region_map_info();
				protobuf::Stored_normal_info* _stored_address_space_info                      	= new (heap) protobuf::Stored_normal_info();

				_stored_address_space->set_size(stored_address_space_size);
				_stored_address_space->set_ds_badge(stored_address_space_ds_badge);
				_stored_address_space->set_sigh_badge(stored_address_space_sigh_badge);

				set_normal_info(heap, stored_address_space, _stored_address_space_info);

                        	_stored_address_space->set_allocated_normal_info(_stored_address_space_info);

				Genode::List<Rtcr::Stored_attached_region_info> _stored_address_space_attached_region_infos	= stored_address_space->stored_attached_region_infos;
				Rtcr::Stored_attached_region_info* address_space_attached_region				= _stored_address_space_attached_region_infos.first();
			
				while(address_space_attached_region){
					Genode::uint16_t attached_ds_badge						= address_space_attached_region->attached_ds_badge;
					Genode::Ram_dataspace_capability rm_memory_content				= address_space_attached_region->memory_content;
					Genode::size_t attached_rm_size							= address_space_attached_region->size;
					Genode::off_t offset                                                            = address_space_attached_region->offset;
                        		Genode::addr_t rel_addr                                                         = address_space_attached_region->rel_addr;
                        		bool executable                                                                 = address_space_attached_region->executable;
			
					protobuf::Stored_attached_region_info* _attached_region				= _stored_address_space->add_stored_attached_region_infos();
					protobuf::Stored_normal_info* _attached_info                                 	= new (heap) protobuf::Stored_normal_info();
                        
					set_normal_info(heap, address_space_attached_region, _attached_info);

					_attached_region->set_attached_ds_badge(attached_ds_badge);
					_attached_region->set_size(attached_rm_size);
					_attached_region->set_offset(offset);
					_attached_region->set_rel_addr(rel_addr);
					_attached_region->set_executable(executable);
                        		_attached_region->set_allocated_normal_info(_attached_info);

					address_space_attached_region=address_space_attached_region->next();

					send_ckpt_dataspace(rm_memory_content, attached_rm_size, _target_socket);
				}

				Rtcr::Stored_region_map_info* stored_stack_area					= &pd_session->stored_stack_area;
				Genode::size_t   stored_stack_area_size						= stored_stack_area->size;
				Genode::uint16_t stored_stack_area_ds_badge					= stored_stack_area->ds_badge;
				Genode::uint16_t stored_stack_area_sigh_badge					= stored_stack_area->sigh_badge;

				protobuf::Stored_region_map_info* _stored_stack_area				= new (heap) protobuf::Stored_region_map_info();
				protobuf::Stored_normal_info* _stored_stack_area_info                           = new (heap) protobuf::Stored_normal_info();
				_stored_stack_area->set_size(stored_stack_area_size);
				_stored_stack_area->set_ds_badge(stored_stack_area_ds_badge);
				_stored_stack_area->set_sigh_badge(stored_stack_area_sigh_badge);
                        
				set_normal_info(heap, stored_stack_area, _stored_stack_area_info);

				_stored_stack_area->set_allocated_normal_info(_stored_stack_area_info);

				Genode::List<Rtcr::Stored_attached_region_info> _stored_stack_area_attached_region_infos	= stored_stack_area->stored_attached_region_infos;
				Rtcr::Stored_attached_region_info* stack_area_attached_region				= _stored_stack_area_attached_region_infos.first();
				
				while(stack_area_attached_region){
					Genode::uint16_t attached_ds_badge						= stack_area_attached_region->attached_ds_badge;
					Genode::Ram_dataspace_capability rm_memory_content				= stack_area_attached_region->memory_content;
					Genode::size_t attached_rm_size							= stack_area_attached_region->size;
					Genode::off_t offset								= stack_area_attached_region->offset;
					Genode::addr_t rel_addr								= stack_area_attached_region->rel_addr;
					bool executable									= stack_area_attached_region->executable;

					protobuf::Stored_attached_region_info* _attached_region				= _stored_stack_area->add_stored_attached_region_infos();
					protobuf::Stored_normal_info* _attached_info				        = new (heap) protobuf::Stored_normal_info();
					_attached_region->set_attached_ds_badge(attached_ds_badge);
					_attached_region->set_size(attached_rm_size);
					_attached_region->set_offset(offset);
					_attached_region->set_rel_addr(rel_addr);
					_attached_region->set_executable(executable);
                        
					set_normal_info(heap, stack_area_attached_region, _attached_info);

					_attached_region->set_allocated_normal_info(_attached_info);

					stack_area_attached_region=stack_area_attached_region->next();

					send_ckpt_dataspace(rm_memory_content, attached_rm_size, _target_socket);
				}

				Rtcr::Stored_region_map_info* stored_linker_area				= &pd_session->stored_linker_area;
				Genode::size_t   stored_linker_area_size					= stored_linker_area->size;
				Genode::uint16_t stored_linker_area_ds_badge					= stored_linker_area->ds_badge;
				Genode::uint16_t stored_linker_area_sigh_badge					= stored_linker_area->sigh_badge;

				protobuf::Stored_region_map_info* _stored_linker_area				= new (heap) protobuf::Stored_region_map_info();
				protobuf::Stored_normal_info* _stored_linker_area_info                          = new (heap) protobuf::Stored_normal_info();
				_stored_linker_area->set_size(stored_linker_area_size);
				_stored_linker_area->set_ds_badge(stored_linker_area_ds_badge);
				_stored_linker_area->set_sigh_badge(stored_linker_area_sigh_badge);

				set_normal_info(heap, stored_linker_area, _stored_linker_area_info);

                        	_stored_linker_area->set_allocated_normal_info(_stored_linker_area_info);

				Genode::List<Rtcr::Stored_attached_region_info> _stored_attached_region_infos	= stored_linker_area->stored_attached_region_infos;
				Rtcr::Stored_attached_region_info* attached_region				= _stored_attached_region_infos.first();
			
				while(attached_region){
					Genode::uint16_t attached_ds_badge						= attached_region->attached_ds_badge;
					Genode::Ram_dataspace_capability rm_memory_content				= attached_region->memory_content;
					Genode::size_t attached_rm_size							= attached_region->size;
					Genode::off_t offset								= attached_region->offset;
					Genode::addr_t rel_addr								= attached_region->rel_addr;
					bool executable									= attached_region->executable;

					protobuf::Stored_attached_region_info* _attached_region				= _stored_linker_area->add_stored_attached_region_infos();
					protobuf::Stored_normal_info* _attached_info                                 	= new (heap) protobuf::Stored_normal_info();
					_attached_region->set_attached_ds_badge(attached_ds_badge);
					_attached_region->set_size(attached_rm_size);
					_attached_region->set_offset(offset);
					_attached_region->set_rel_addr(rel_addr);
					_attached_region->set_executable(executable);

					set_normal_info(heap, attached_region, _attached_info);

                        		_attached_region->set_allocated_normal_info(_attached_info);

					attached_region=attached_region->next();

					send_ckpt_dataspace(rm_memory_content, attached_rm_size, _target_socket);
				}

				Genode::List<Rtcr::Stored_signal_context_info> stored_context_infos 		= pd_session->stored_context_infos;
				Genode::List<Rtcr::Stored_signal_source_info> stored_source_infos 		= pd_session->stored_source_infos;
				Genode::List<Rtcr::Stored_native_capability_info> stored_native_cap_infos 	= pd_session->stored_native_cap_infos;

				Rtcr::Stored_signal_context_info* context 					= stored_context_infos.first();
				while(context) {
					Genode::uint16_t signal_source_badge                                    = context->signal_source_badge;
                        		unsigned long imprint                                                   = context->imprint;

					protobuf::Stored_signal_context_info* _context                          = _pd->add_stored_context_infos();
					protobuf::Stored_normal_info* _context_info                             = new (heap) protobuf::Stored_normal_info();
                        		_context->set_signal_source_badge(signal_source_badge);
                        		_context->set_imprint(imprint);

					set_normal_info(heap, context, _context_info);

                        		_context->set_allocated_normal_info(_context_info);

					context=context->next();
				}

				Rtcr::Stored_signal_source_info* source 					= stored_source_infos.first();
                       		while(source) {
					protobuf::Stored_signal_source_info* _source                            = _pd->add_stored_source_infos();
					protobuf::Stored_normal_info* _source_info                              = new (heap) protobuf::Stored_normal_info();

					set_normal_info(heap, source, _source_info);

					_source->set_allocated_normal_info(_source_info);

					source=source->next();
				}

				Rtcr::Stored_native_capability_info* native_capability 				= stored_native_cap_infos.first();
                        	while(native_capability) {
					Genode::uint16_t ep_badge                                               = native_capability->ep_badge;

					protobuf::Stored_native_capability_info* _cap                           = _pd->add_stored_native_cap_infos();
                        		protobuf::Stored_normal_info* _cap_info                              	= new (heap) protobuf::Stored_normal_info();
					_cap->set_signal_source_badge(ep_badge);
                        		set_normal_info(heap, native_capability, _cap_info);

					_cap->set_allocated_normal_info(_cap_info);

					native_capability=native_capability->next();
				}
				_pd->set_allocated_stored_address_space(_stored_address_space);
				_pd->set_allocated_stored_stack_area(_stored_stack_area);
				_pd->set_allocated_stored_linker_area(_stored_linker_area);
			
				pd_session=pd_session->next();

			}

			/* CPU Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_cpu_session_info> _stored_cpu_sessions 		= ts._stored_cpu_sessions;
			Rtcr::Stored_cpu_session_info* cpu_session 					= _stored_cpu_sessions.first();
			while(cpu_session) {
				Genode::uint16_t cpu_session_sigh_badge						= cpu_session->sigh_badge;

				protobuf::Stored_cpu_session_info* _cpu_session 				= _ts.add__stored_cpu_sessions();
				protobuf::Stored_session_info* _cpu_session_info                                 = new (heap) protobuf::Stored_session_info();
				_cpu_session->set_sigh_badge(cpu_session_sigh_badge);

				set_session_info(heap, cpu_session, _cpu_session_info);

				_cpu_session->set_allocated_session_info(_cpu_session_info);
			
				Genode::List<Rtcr::Stored_cpu_thread_info> stored_cpu_thread_infos		= cpu_session->stored_cpu_thread_infos;
				Rtcr::Stored_cpu_thread_info* cpu_thread					= stored_cpu_thread_infos.first();
				
				while(cpu_thread) {
					Genode::uint16_t pd_session_badge						= cpu_thread->pd_session_badge;
					Genode::Cpu_session::Name name							= cpu_thread->name;
					Genode::Cpu_session::Weight weight						= cpu_thread->weight;
					Genode::addr_t utcb								= cpu_thread->utcb;
					bool started									= cpu_thread->started;
					bool paused									= cpu_thread->paused;
					bool single_step								= cpu_thread->single_step;
					Genode::Affinity::Location affinity						= cpu_thread->affinity;
					Genode::uint16_t cpu_thread_sigh_badge						= cpu_thread->sigh_badge;
					Genode::Thread_state target_state						= cpu_thread->ts;
			
					protobuf::Stored_cpu_thread_info* _cpu_thread                                   = _cpu_session->add_stored_cpu_thread_infos();
					protobuf::Stored_normal_info* _cpu_normal_info                            	= new (heap) protobuf::Stored_normal_info();

					set_normal_info(heap, cpu_thread, _cpu_normal_info);

                        		_cpu_thread->set_allocated_normal_info(_cpu_normal_info);
					_cpu_thread->set_pd_session_badge(pd_session_badge);
					_cpu_thread->set_name(name.string());
					_cpu_thread->set_weight(std::to_string(weight.value).c_str());
					_cpu_thread->set_utcb(utcb);
					_cpu_thread->set_started(started);
					_cpu_thread->set_paused(paused);
					_cpu_thread->set_single_step(single_step);
					_cpu_thread->set_affinity(affinity.xpos());
					_cpu_thread->set_sigh_badge(cpu_thread_sigh_badge);
					_cpu_thread->set_ts(target_state.exception);

					cpu_thread=cpu_thread->next();

				}
				cpu_session=cpu_session->next();
			}

			/* RAM Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_ram_session_info> _stored_ram_sessions 		= ts._stored_ram_sessions;
			Rtcr::Stored_ram_session_info* ram_session					= _stored_ram_sessions.first();
			while(ram_session) {
				protobuf::Stored_ram_session_info* _ram_session					= _ts.add__stored_ram_sessions();
				protobuf::Stored_session_info* _ram_session_info                                 = new (heap) protobuf::Stored_session_info();

				set_session_info(heap, ram_session, _ram_session_info);

                        	_ram_session->set_allocated_session_info(_ram_session_info);

				Genode::List<Rtcr::Stored_ram_dataspace_info> stored_ramds_infos		= ram_session->stored_ramds_infos;
				Rtcr::Stored_ram_dataspace_info* ramds						= stored_ramds_infos.first();
				while(ramds) {
					Genode::Ram_dataspace_capability ram_memory_content				= ramds->memory_content;
					Genode::size_t ram_size								= ramds->size;			
					Genode::Cache_attribute cached							= ramds->cached;
					bool managed									= ramds->managed;
					Genode::size_t timestamp							= ramds->timestamp;
		
					protobuf::Stored_ram_dataspace_info* _ram_ds								= _ram_session->add_stored_ramds_infos();
					_ram_ds->set_size(ram_size);
					_ram_ds->set_cached(cached);
					_ram_ds->set_managed(managed);
					_ram_ds->set_timestamp(timestamp);
					protobuf::Stored_normal_info* _ram_normal_info                                		= new (heap) protobuf::Stored_normal_info();

					set_normal_info(heap, ramds, _ram_normal_info);

                        		_ram_ds->set_allocated_normal_info(_ram_normal_info);

					send_ckpt_dataspace(ram_memory_content, ram_size, _target_socket);

					ramds=ramds->next();

				}
				ram_session=ram_session->next();
			}

			/* ROM Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_rom_session_info> _stored_rom_sessions 		= ts._stored_rom_sessions;
			Rtcr::Stored_rom_session_info* rom_session					= _stored_rom_sessions.first();
			while(rom_session){
				Genode::uint16_t dataspace_badge						= rom_session->dataspace_badge;
				Genode::uint16_t rom_sigh_badge							= rom_session->sigh_badge;
				/* protobuf */
				protobuf::Stored_rom_session_info* _rom_session							= _ts.add__stored_rom_sessions();
				protobuf::Stored_session_info* _rom_session_info                                  = new (heap) protobuf::Stored_session_info();

				set_session_info(heap, rom_session, _rom_session_info);

                        	_rom_session->set_allocated_session_info(_rom_session_info);
				_rom_session->set_dataspace_badge(dataspace_badge);
				_rom_session->set_sigh_badge(rom_sigh_badge);

				rom_session=rom_session->next();
			}

			/* RM Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_rm_session_info> _stored_rm_sessions 			= ts._stored_rm_sessions;
			Rtcr::Stored_rm_session_info* rm_session					= _stored_rm_sessions.first();
			while(rm_session){
							protobuf::Stored_rm_session_info* _rm_session							= _ts.add__stored_rm_sessions();
				protobuf::Stored_session_info* _rm_session_info                                  	= new (heap) protobuf::Stored_session_info();
				
				set_session_info(heap, rm_session, _rm_session_info);

                        	_rm_session->set_allocated_session_info(_rm_session_info);

				Genode::List<Rtcr::Stored_region_map_info> _stored_region_map_infos		= rm_session->stored_region_map_infos;
				Rtcr::Stored_region_map_info* region_map					= _stored_region_map_infos.first();
				while(region_map){
			
					Genode::size_t   rm_size							= region_map->size;
					Genode::uint16_t ds_badge							= region_map->ds_badge;
					Genode::uint16_t rm_sigh_badge							= region_map->sigh_badge;

					protobuf::Stored_region_map_info* _region_map				= _rm_session->add_stored_region_map_infos();
					protobuf::Stored_normal_info* _rm_normal_info                          	= new (heap) protobuf::Stored_normal_info();

					set_normal_info(heap, region_map, _rm_normal_info);

					_region_map->set_size(rm_size);
					_region_map->set_ds_badge(ds_badge);
					_region_map->set_sigh_badge(rm_sigh_badge);
                        		_region_map->set_allocated_normal_info(_rm_normal_info);

					Genode::List<Rtcr::Stored_attached_region_info> _stored_attached_region_infos	= region_map->stored_attached_region_infos;
					Rtcr::Stored_attached_region_info* attached_region				= _stored_attached_region_infos.first();
					while(attached_region){
			
						Genode::uint16_t attached_ds_badge						= attached_region->attached_ds_badge;
						Genode::Ram_dataspace_capability rm_memory_content				= attached_region->memory_content;
						Genode::size_t attached_rm_size							= attached_region->size;
						Genode::off_t offset								= attached_region->offset;
						Genode::addr_t rel_addr								= attached_region->rel_addr;
						bool executable									= attached_region->executable;
			
						protobuf::Stored_attached_region_info* _attached_region				= _region_map->add_stored_attached_region_infos();
						protobuf::Stored_normal_info* _attached_normal_info                                 = new (heap) protobuf::Stored_normal_info();

						set_normal_info(heap, attached_region, _attached_normal_info);

						_attached_region->set_attached_ds_badge(attached_ds_badge);
						_attached_region->set_size(attached_rm_size);
						_attached_region->set_offset(offset);
						_attached_region->set_rel_addr(rel_addr);
						_attached_region->set_executable(executable);
                        			_attached_region->set_allocated_normal_info(_attached_normal_info);

						send_ckpt_dataspace(rm_memory_content, attached_rm_size, _target_socket);

						attached_region=attached_region->next();
					}
					region_map=region_map->next();
				}
				rm_session=rm_session->next();
			}

			/* LOG Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_log_session_info> _stored_log_sessions 		= ts._stored_log_sessions;
			Rtcr::Stored_log_session_info* log_session					= _stored_log_sessions.first();
			while(log_session) {

				protobuf::Stored_log_session_info* _log_session				= _ts.add__stored_log_sessions();
				protobuf::Stored_session_info* _log_session_info                        = new (heap) protobuf::Stored_session_info();

				set_session_info(heap, log_session, _log_session_info);

				_log_session->set_allocated_session_info(_log_session_info);
			
				log_session=log_session->next();
			}

			/* Timer Session */
			/* rtcr */
			Genode::List<Rtcr::Stored_timer_session_info> _stored_timer_sessions 		= ts._stored_timer_sessions;
			Rtcr::Stored_timer_session_info* timer_session					= _stored_timer_sessions.first();
			while(timer_session) {
				Genode::uint16_t timer_sigh_badge						= timer_session->sigh_badge;
				unsigned         timeout							= timer_session->timeout;
				bool             periodic							= timer_session->periodic;
				/* protobuf */
				protobuf::Stored_timer_session_info* _timer_session				= _ts.add__stored_timer_sessions();
				protobuf::Stored_session_info* _timer_session_info                              = new (heap) protobuf::Stored_session_info();
			
				set_session_info(heap, timer_session, _timer_session_info);

				_timer_session->set_allocated_session_info(_timer_session_info);
				_timer_session->set_sigh_badge(timer_sigh_badge);
				_timer_session->set_timeout(timeout);
				_timer_session->set_periodic(periodic);
			
				timer_session=timer_session->next();
			}
			
			/* String target state is serialized to */
                        std::string foo;
                        /* Serialize target state to String */
                        _ts.SerializeToString(&foo);
			PDBG("Serialize completed");
                        /* Get size of serialized String */
                        int32_t m_length=foo.size();
			PDBG("size of target state is %d", m_length);
                        /* Send size of serialized String to somewhere */
                        lwip_write(_target_socket,&m_length,4);
			PDBG("Length written");
                        /* Send serialized String to other machine */
			lwip_write(_target_socket,(void*)foo.c_str(),foo.size());
			PDBG("Done checkpoint");
		}
		else if (message == RESTORE)
		{
			Genode::Heap              heap            { _env.ram(), _env.rm() };
			Genode::Service_registry  parent_services { };
			Rtcr::Target_child child_restored { _env, heap, parent_services, "sheep_counter", 0 };
			Rtcr::Target_state ts(_env, heap);
			protobuf::Target_state _ts;
			
			int size=0;
			lwip_read(_target_socket, &size, 4);
			size=ntohl(size);
			PDBG("Receive target state of size %d",size);
			Genode::Ram_dataspace_capability state_ds=Genode::env()->ram_session()->alloc(size);
			char* bar=Genode::env()->rm_session()->attach(state_ds);	
			lwip_read(_target_socket, bar, size);
			PDBG("Receive done");
			_ts.ParseFromArray(bar,size);
			PDBG("Parsed from array");
			ts._cap_idx_alloc_addr=_ts._cap_idx_alloc_addr();

			/* PD Session */
			/* protobuf */
			PDBG("%d PD Sessions found",_ts._stored_pd_sessions_size());
			for(int i=0;i<_ts._stored_pd_sessions_size();i++){
				protobuf::Stored_pd_session_info _pd 				= _ts._stored_pd_sessions(i);
			
				Rtcr::Stored_region_map_info *_pd_stored_address_space		= new (heap) Rtcr::Stored_region_map_info(
												_pd.stored_address_space().normal_info().general_info().kcap(),
												_pd.stored_address_space().normal_info().general_info().badge(),
												_pd.stored_address_space().normal_info().general_info().bootstrapped(),
												_pd.stored_address_space().size(),
												_pd.stored_address_space().ds_badge(),
												_pd.stored_address_space().sigh_badge());
        		
				Rtcr::Stored_region_map_info *_pd_stored_stack_area  		= new (heap) Rtcr::Stored_region_map_info(
												_pd.stored_stack_area().normal_info().general_info().kcap(),
												_pd.stored_stack_area().normal_info().general_info().badge(),
												_pd.stored_stack_area().normal_info().general_info().bootstrapped(),
												_pd.stored_stack_area().size(),
												_pd.stored_stack_area().ds_badge(),
												_pd.stored_stack_area().sigh_badge());

				Rtcr::Stored_region_map_info *_pd_stored_linker_area 		= new (heap) Rtcr::Stored_region_map_info(
												_pd.stored_linker_area().normal_info().general_info().kcap(),
												_pd.stored_linker_area().normal_info().general_info().badge(),
												_pd.stored_linker_area().normal_info().general_info().bootstrapped(),
												_pd.stored_linker_area().size(),
												_pd.stored_linker_area().ds_badge(),
												_pd.stored_linker_area().sigh_badge());

				Genode::List<Rtcr::Stored_pd_session_info> *_stored_pd_sessions = &ts._stored_pd_sessions;
				Rtcr::Stored_pd_session_info *pd_session 			= new (heap) Rtcr::Stored_pd_session_info(
												_pd.session_info().creation_args().c_str(),
												_pd.session_info().upgrade_args().c_str(),
												_pd.session_info().general_info().kcap(),
												_pd.session_info().general_info().badge(),
												_pd.session_info().general_info().bootstrapped(),
												_pd_stored_address_space,
												_pd_stored_stack_area,
												_pd_stored_linker_area);
				_stored_pd_sessions->insert(pd_session);

				Genode::List<Rtcr::Stored_attached_region_info> *_address_space_stored_attached_region_infos   = &pd_session->stored_address_space.stored_attached_region_infos;
                        
				for(int k=0; k<_pd.stored_address_space().stored_attached_region_infos_size(); k++) {
                        		protobuf::Stored_attached_region_info _attached_region                          = _pd.stored_address_space().stored_attached_region_infos(k);

                        		Genode::Ram_dataspace_capability _rm_memory_content                             = _env.ram().alloc(_attached_region.size());

					recv_ckpt_dataspace(_rm_memory_content, _attached_region.size(), _target_socket);

                        		Rtcr::Stored_attached_region_info *attached_region	= new (heap) Rtcr::Stored_attached_region_info(
												_attached_region.normal_info().general_info().kcap(),
												_attached_region.normal_info().general_info().badge(),
												_attached_region.normal_info().general_info().bootstrapped(),
												_attached_region.attached_ds_badge(),
												_rm_memory_content,
												_attached_region.size(),
												_attached_region.offset(),
												_attached_region.rel_addr(),
												_attached_region.executable());
                        		_address_space_stored_attached_region_infos->insert(attached_region);
                        	}

                        	Genode::List<Rtcr::Stored_attached_region_info> *_stack_area_stored_attached_region_infos   = &pd_session->stored_stack_area.stored_attached_region_infos;

                        	for(int k=0; k<_pd.stored_stack_area().stored_attached_region_infos_size(); k++) {
                        		protobuf::Stored_attached_region_info _attached_region                          = _pd.stored_stack_area().stored_attached_region_infos(k);
                        
					Genode::Ram_dataspace_capability _rm_memory_content                             = _env.ram().alloc(_attached_region.size());

					recv_ckpt_dataspace(_rm_memory_content, _attached_region.size(), _target_socket);

                        		Rtcr::Stored_attached_region_info *attached_region	= new (heap) Rtcr::Stored_attached_region_info(
												_attached_region.normal_info().general_info().kcap(),
												_attached_region.normal_info().general_info().badge(),
												_attached_region.normal_info().general_info().bootstrapped(),
												_attached_region.attached_ds_badge(),
												_rm_memory_content,
												_attached_region.size(),
												_attached_region.offset(),
												_attached_region.rel_addr(),
												_attached_region.executable());

                        		_stack_area_stored_attached_region_infos->insert(attached_region);
                       		}

				Genode::List<Rtcr::Stored_attached_region_info> *_linker_area_stored_attached_region_infos   = &pd_session->stored_linker_area.stored_attached_region_infos;
                        
                        	for(int k=0; k<_pd.stored_linker_area().stored_attached_region_infos_size(); k++) {
                       			protobuf::Stored_attached_region_info _attached_region                          = _pd.stored_linker_area().stored_attached_region_infos(k);
                        
					Genode::Ram_dataspace_capability _rm_memory_content                             = _env.ram().alloc(_attached_region.size());

					recv_ckpt_dataspace(_rm_memory_content, _attached_region.size(), _target_socket);

                        		Rtcr::Stored_attached_region_info *attached_region	= new (heap) Rtcr::Stored_attached_region_info(
												_attached_region.normal_info().general_info().kcap(),
												_attached_region.normal_info().general_info().badge(),
												_attached_region.normal_info().general_info().bootstrapped(),
												_attached_region.attached_ds_badge(),
												_rm_memory_content,
												_attached_region.size(),
												_attached_region.offset(),
												_attached_region.rel_addr(),
												_attached_region.executable());

                        		_linker_area_stored_attached_region_infos->insert(attached_region);
                        	}

				Genode::List<Rtcr::Stored_signal_context_info>* _stored_context_infos 		= &pd_session->stored_context_infos;
				Genode::List<Rtcr::Stored_signal_source_info>* _stored_source_infos 		= &pd_session->stored_source_infos;
				Genode::List<Rtcr::Stored_native_capability_info>* _stored_native_cap_infos 	= &pd_session->stored_native_cap_infos;

				for(int j=0;j<_pd.stored_context_infos_size(); j++){
					protobuf::Stored_signal_context_info _context				= _pd.stored_context_infos(j);
					Rtcr::Stored_signal_context_info *stored_signal_context			= new (heap) Rtcr::Stored_signal_context_info(
														_context.normal_info().general_info().kcap(),
														_context.normal_info().general_info().badge(),
														_context.normal_info().general_info().bootstrapped(),
														_context.signal_source_badge(),
														_context.imprint());
					_stored_context_infos->insert(stored_signal_context);
				}

				for(int k=0;k<_pd.stored_source_infos_size(); k++){
					protobuf::Stored_signal_source_info _source 				= _pd.stored_source_infos(k);
					Rtcr::Stored_signal_source_info *stored_signal_source			= new (heap) Rtcr::Stored_signal_source_info(
														_source.normal_info().general_info().kcap(),
														_source.normal_info().general_info().badge(),
														_source.normal_info().general_info().bootstrapped());
					_stored_source_infos->insert(stored_signal_source);
				}

				for(int l=0;l<_pd.stored_native_cap_infos_size(); l++){
					protobuf::Stored_native_capability_info _cap 				= _pd.stored_native_cap_infos(l);
					Rtcr::Stored_native_capability_info *stored_cap				= new (heap) Rtcr::Stored_native_capability_info(
														_cap.normal_info().general_info().kcap(),
														_cap.normal_info().general_info().badge(),
														_cap.normal_info().general_info().bootstrapped(),
														_cap.signal_source_badge());
				_stored_native_cap_infos->insert(stored_cap);
				}

			}

			/* CPU Session */
                        /* protobuf */
			PDBG("%d CPU Sessions found",_ts._stored_cpu_sessions_size());
			for(int i=0;i<_ts._stored_cpu_sessions_size();i++) {
                        	protobuf::Stored_cpu_session_info _cpu_session                          = _ts._stored_cpu_sessions(i);

				Genode::List<Rtcr::Stored_cpu_session_info>* _stored_cpu_sessions       = &ts._stored_cpu_sessions;
				Rtcr::Stored_cpu_session_info *cpu_session				= new (heap) Rtcr::Stored_cpu_session_info(
													_cpu_session.session_info().creation_args().c_str(),
													_cpu_session.session_info().upgrade_args().c_str(),
													_cpu_session.session_info().general_info().kcap(),
													_cpu_session.session_info().general_info().badge(),
													_cpu_session.session_info().general_info().bootstrapped(),
													_cpu_session.sigh_badge());
				_stored_cpu_sessions->insert(cpu_session);
				Genode::List<Rtcr::Stored_cpu_thread_info>* stored_cpu_thread_infos     = &cpu_session->stored_cpu_thread_infos;

				for(int j=0; j<_cpu_session.stored_cpu_thread_infos_size(); j++) {
                        		protobuf::Stored_cpu_thread_info _cpu_thread                    = _cpu_session.stored_cpu_thread_infos(j);
                  			Rtcr::Stored_cpu_thread_info *cpu_thread			= new (heap) Rtcr::Stored_cpu_thread_info(
													_cpu_thread.normal_info().general_info().kcap(),
													_cpu_thread.normal_info().general_info().badge(),
													_cpu_thread.normal_info().general_info().bootstrapped(),
													_cpu_thread.pd_session_badge(),
													_cpu_thread.name().c_str(),
													Genode::Cpu_session::Weight(),
													_cpu_thread.utcb(),
													_cpu_thread.started(),
													_cpu_thread.paused(),
													_cpu_thread.single_step(),
													Genode::Affinity::Location(_cpu_thread.affinity(),0),
													_cpu_thread.sigh_badge());
					stored_cpu_thread_infos->insert(cpu_thread);
				}

			}

			/* RAM Session */
                        /* protobuf */
			for(int i=0;i<_ts._stored_ram_sessions_size();i++) {
                        	protobuf::Stored_ram_session_info _ram_session                                  = _ts._stored_ram_sessions(i);
			
				Genode::List<Rtcr::Stored_ram_session_info>* _stored_ram_sessions       = &ts._stored_ram_sessions;
                        	Rtcr::Stored_ram_session_info *ram_session                              = new (heap) Rtcr::Stored_ram_session_info(
													_ram_session.session_info().creation_args().c_str(),
													_ram_session.session_info().upgrade_args().c_str(),
													_ram_session.session_info().general_info().kcap(),
													_ram_session.session_info().general_info().badge(),
													_ram_session.session_info().general_info().bootstrapped());
				_stored_ram_sessions->insert(ram_session);

				Genode::List<Rtcr::Stored_ram_dataspace_info>* stored_ramds_infos       = &ram_session->stored_ramds_infos;

				for(int j=0; j<_ram_session.stored_ramds_infos_size(); j++) {
                        		protobuf::Stored_ram_dataspace_info _ramds                      = _ram_session.stored_ramds_infos(j);
					Genode::Ram_dataspace_capability _ram_memory_content            = Genode::env()->ram_session()->alloc(_ramds.size());
					char* _ram_content						= (char*)Genode::env()->rm_session()->attach(_ram_memory_content);
					
					recv_ckpt_dataspace(_ram_memory_content, _ramds.size(), _target_socket);

                       			Rtcr::Stored_ram_dataspace_info *ramds                          = new (heap) Rtcr::Stored_ram_dataspace_info(
													_ramds.normal_info().general_info().kcap(),
													_ramds.normal_info().general_info().badge(),
													_ramds.normal_info().general_info().bootstrapped(),
													_ram_memory_content,
													_ramds.size(),
													(Genode::Cache_attribute)_ramds.cached(),
													_ramds.managed(),
													_ramds.timestamp());
					stored_ramds_infos->insert(ramds);
				}

			}

                        /* ROM Session */
                        /* protobuf */
			PDBG("%d ROM Sessions found",_ts._stored_rom_sessions_size());
			for(int i=0;i<_ts._stored_rom_sessions_size();i++) {
                        	protobuf::Stored_rom_session_info _rom_session                          = _ts._stored_rom_sessions(i);
                        	Genode::List<Rtcr::Stored_rom_session_info>* _stored_rom_sessions       = &ts._stored_rom_sessions;
                        	Rtcr::Stored_rom_session_info *rom_session                              = new (heap) Rtcr::Stored_rom_session_info(
													_rom_session.session_info().creation_args().c_str(),
													_rom_session.session_info().upgrade_args().c_str(),
													_rom_session.session_info().general_info().kcap(),
													_rom_session.session_info().general_info().badge(),
													_rom_session.session_info().general_info().bootstrapped(),
													_rom_session.dataspace_badge(),
													_rom_session.sigh_badge());
				_stored_rom_sessions->insert(rom_session);
			}

                        /* RM Session */
                        /* protobuf */
			PDBG("%d RM Sessions found",_ts._stored_rm_sessions_size());
			for(int i=0;i<_ts._stored_rm_sessions_size();i++) {
                        	protobuf::Stored_rm_session_info _rm_session                            = _ts._stored_rm_sessions(i);

				Genode::List<Rtcr::Stored_rm_session_info>* _stored_rm_sessions         = &ts._stored_rm_sessions;
				Rtcr::Stored_rm_session_info *rm_session                                = new (heap) Rtcr::Stored_rm_session_info(
													_rm_session.session_info().creation_args().c_str(),
													_rm_session.session_info().upgrade_args().c_str(),
													_rm_session.session_info().general_info().kcap(),
													_rm_session.session_info().general_info().badge(),
													_rm_session.session_info().general_info().bootstrapped());
			
				_stored_rm_sessions->insert(rm_session);
                        
				Genode::List<Rtcr::Stored_region_map_info>* _stored_region_map_infos    = &rm_session->stored_region_map_infos;
			
				for(int j=0; j<_rm_session.stored_region_map_infos_size(); j++) {
					protobuf::Stored_region_map_info _region_map                    = _rm_session.stored_region_map_infos(j);
					Rtcr::Stored_region_map_info *region_map                        = new (heap) Rtcr::Stored_region_map_info(
													_region_map.normal_info().general_info().kcap(),
													_region_map.normal_info().general_info().badge(),
													_region_map.normal_info().general_info().bootstrapped(),
													_region_map.size(),
													_region_map.ds_badge(),
													_region_map.sigh_badge());
					_stored_region_map_infos->insert(region_map);

					Genode::List<Rtcr::Stored_attached_region_info>* _stored_attached_region_infos   = &region_map->stored_attached_region_infos;

					for(int k=0; k<_region_map.stored_attached_region_infos_size(); k++) {
                        			protobuf::Stored_attached_region_info _attached_region  = _region_map.stored_attached_region_infos(k);
						Genode::Ram_dataspace_capability _rm_memory_content     = Genode::env()->ram_session()->alloc(_attached_region.size());
						
						recv_ckpt_dataspace(_rm_memory_content, _attached_region.size(), _target_socket);

                        			Rtcr::Stored_attached_region_info *attached_region      = new (heap) Rtcr::Stored_attached_region_info(
													_attached_region.normal_info().general_info().kcap(),
													_attached_region.normal_info().general_info().badge(),
													_attached_region.normal_info().general_info().bootstrapped(),
													_attached_region.attached_ds_badge(),
													_rm_memory_content,
													_attached_region.size(),
													_attached_region.offset(),
													_attached_region.rel_addr(),
													_attached_region.executable());
						_stored_attached_region_infos->insert(attached_region);
			
					}

				}

			}

                        /* LOG Session */
                        PDBG("%d Log Sessions found",_ts._stored_log_sessions_size());
                        for(int i=0;i<_ts._stored_log_sessions_size();i++) {
                        	protobuf::Stored_log_session_info _log_session                          = _ts._stored_log_sessions(i);
                        	Genode::List<Rtcr::Stored_log_session_info>* _stored_log_sessions     	= &ts._stored_log_sessions;
                        	Rtcr::Stored_log_session_info *log_session                              = new (heap) Rtcr::Stored_log_session_info(
													_log_session.session_info().creation_args().c_str(),
													_log_session.session_info().upgrade_args().c_str(),
													_log_session.session_info().general_info().kcap(),
													_log_session.session_info().general_info().badge(),
													_log_session.session_info().general_info().bootstrapped());
                        	_stored_log_sessions->insert(log_session); 
			}

                        /* Timer Session */
                        /* protobuf */
			PDBG("%d Timer Sessions found",_ts._stored_timer_sessions_size());
			for(int i=0;i<_ts._stored_timer_sessions_size();i++) {
                        	protobuf::Stored_timer_session_info _timer_session                      = _ts._stored_timer_sessions(i);
                        	Genode::List<Rtcr::Stored_timer_session_info>* _stored_timer_sessions   = &ts._stored_timer_sessions;
                       		Rtcr::Stored_timer_session_info *timer_session                          = new (heap) Rtcr::Stored_timer_session_info(
													_timer_session.session_info().creation_args().c_str(),
													_timer_session.session_info().upgrade_args().c_str(),
													_timer_session.session_info().general_info().kcap(),
													_timer_session.session_info().general_info().badge(),
													_timer_session.session_info().general_info().bootstrapped(),
													_timer_session.sigh_badge(),
													_timer_session.timeout(),
													_timer_session.periodic());
				_stored_timer_sessions->insert(timer_session);
			}

			PDBG("TIMER Session %p", &(ts._stored_timer_sessions.first()->badge));
                        PDBG("TIMER Session %d", ts._stored_timer_sessions.first()->badge);
			PDBG("CPU Session %p", &(ts._stored_cpu_sessions.first()->badge));
                        PDBG("CPU Session %d", ts._stored_cpu_sessions.first()->badge);
			PDBG("RAM Session %p", &(ts._stored_ram_sessions.first()->badge));
			PDBG("RAM Session %d", ts._stored_ram_sessions.first()->badge);
			PDBG("PD Session %p", &(ts._stored_pd_sessions.first()->badge));
                        PDBG("PD Session %d", ts._stored_pd_sessions.first()->badge);
			//PDBG("Child");
			//Rtcr::Target_child child_restored { _env, heap, parent_services, "sheep_counter", 0 };
			//PDBG("Restorer");
			Rtcr::Restorer resto(heap, child_restored, ts);
			child_restored.start(resto);
			//PDBG("PD Session %p", &(ts._stored_pd_sessions.first()->badge));
			//PDBG("PD Session %d", ts._stored_pd_sessions.first()->badge);
			//child_restored.start(resto);
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
