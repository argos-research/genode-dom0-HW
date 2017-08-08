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

Dom0_server::Dom0_server() :
	_listen_socket(0),
	_in_addr{0},
	_target_addr{0},
	_task_loader{},
	_parser{}
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
		if (message == SEND_DESCS)
		{
			PDBG("Ready to receive task description.");

			// Get XML size.
			int xml_size;
			NETCHECK_LOOP(receiveInt32_t(xml_size));
			Genode::Attached_ram_dataspace xml_ds(Genode::env()->ram_session(), xml_size);
			PINF("Ready to receive XML of size %d.", xml_size);

			// Get XML file.
			NETCHECK_LOOP(receive_data(xml_ds.local_addr<char>(), xml_size));
			PDBG("Received XML. Initializing tasks.");
			_task_loader.add_tasks(xml_ds.cap());

			PDBG("Done with reveiving task description.");

			// Parse XML file to receive the optimization goal.
			//_controller.set_opt_goal(xml_ds.cap());

		}
		else if (message == CLEAR)
		{
			PDBG("Clearing tasks.");
			_task_loader.clear_tasks();
			PDBG("Done with cleaning tasks.");
		}
		else if (message == SEND_BINARIES)
		{
			PDBG("Ready to receive binaries.");

			// Get number of binaries to receive.
			int num_binaries = 0;
			NETCHECK_LOOP(receiveInt32_t(num_binaries));
			PINF("%d binar%s to be sent.", num_binaries, num_binaries == 1 ? "y" : "ies");

			// Receive binaries.
			for (int i = 0; i < num_binaries; i++)
			{
				// Client is waiting for ready signal.
				NETCHECK_LOOP(sendInt32_t(GO_SEND));

				// Get binary name.
				Genode::Attached_ram_dataspace name_ds(Genode::env()->ram_session(), 16);
				NETCHECK_LOOP(receive_data(name_ds.local_addr<char>(), 16));

				// Get binary size.
				int32_t binary_size = 0;
				NETCHECK_LOOP(receiveInt32_t(binary_size));

				// Get binary data.
				Genode::Dataspace_capability binDsCap = _task_loader.binary_ds(name_ds.cap(), binary_size);
				Genode::Rm_session* rm = Genode::env()->rm_session();
				char* bin = (char*)rm->attach(binDsCap);
				NETCHECK_LOOP(receive_data(bin, binary_size));

				PINF("Got binary '%s' of size %d.", name_ds.local_addr<char>(), binary_size);
				rm->detach(bin);
			}
			PDBG("Done with receiving binaries.");
		}
		else if (message == GET_LIVE)
		{
			//stats_proto stats = {};
			//char *name="dom0";
			//stats_display();
			//stats_display_proto(&stats, name);
			Genode::Dataspace_capability xmlDsCap = _parser.live_data();
			Genode::Rm_session* rm = Genode::env()->rm_session();
			char* xml = (char*)rm->attach(xmlDsCap);

			size_t size = std::strlen(xml) + 1;
			//PINF("Sending profile data of size %d", size);
			NETCHECK_LOOP(sendInt32_t(size));
			NETCHECK_LOOP(send_data(xml, size));

			rm->detach(xml);
			//PDBG("Done.");
		}
		else if (message == START)
		{
			// start optimization
			PDBG("Sarting the optimization.");
			_controller.optimize();
			PDBG("Done with starting the optimization.");
			
			// start the tasks
			PDBG("Starting tasks.");
			_task_loader.start();
			PDBG("Done with starting tasks.");
		}
		else if (message == STOP)
		{
			PDBG("Stopping tasks.");
			_task_loader.stop();
			PDBG("Done with stopping tasks.");
		}
		/*else if (message == GET_PROFILE)
		{
			Genode::Dataspace_capability xmlDsCap = _parser.profile_data();
			Genode::Rm_session* rm = Genode::env()->rm_session();
			char* xml = (char*)rm->attach(xmlDsCap);

			size_t size = std::strlen(xml) + 1;
			PINF("Sending profile data of size %d", size);
			NETCHECK_LOOP(sendInt32_t(size));
			NETCHECK_LOOP(send_data(xml, size));

			rm->detach(xml);
			PDBG("Done.");
		}*/

		else if (message == OPTIMIZE)
		{

			PDBG("Ready to receive optimization goal.");

			// Get XML size.
			int xml_size;
			NETCHECK_LOOP(receiveInt32_t(xml_size));
			Genode::Attached_ram_dataspace xml_ds(Genode::env()->ram_session(), xml_size);
			PINF("Ready to receive XML of size %d.", xml_size);

			// Get XML file.
			NETCHECK_LOOP(receive_data(xml_ds.local_addr<char>(), xml_size));
			PDBG("Received XML. Setting optimization goal.");
			_controller.set_opt_goal(xml_ds.cap());
			PDBG("Done with receiving optimization goal.");
			
		}

		else
		{
			PWRN("Unknown message: %d", message);
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
