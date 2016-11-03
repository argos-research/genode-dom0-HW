#include "dom0_server.h"

#include <cstring>
#include <vector>
#include <string>

#include <base/printf.h>
#include <lwip/genode.h>
#include <os/attached_ram_dataspace.h>

#include "config.h"
#include "communication_magic_numbers.h"

Dom0_server::Dom0_server() :
	_listen_socket(0),
	_in_addr{0},
	_target_addr{0},
	_task_manager{}
{
	lwip_tcpip_init();

	const Config& config = Config::get();

	_in_addr.sin_family = AF_INET;
	_in_addr.sin_port = htons(config.port);
	if (std::strcmp(config.dhcp, "yes") == 0)
	{
		if (lwip_nic_init(0, 0, 0, config.buf_size, config.buf_size)) {
			PERR("We got no IP address!");
			return;
		}
		_in_addr.sin_addr.s_addr = INADDR_ANY;
	}
	else
	{
		if (lwip_nic_init(inet_addr(config.listen_address), inet_addr(config.network_mask), inet_addr(config.network_gateway), config.buf_size, config.buf_size)) {
			PERR("We got no IP address!");
			return;
		}
		_in_addr.sin_addr.s_addr = inet_addr(config.listen_address);
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
			_task_manager.add_tasks(xml_ds.cap());
			PDBG("Done.");
		}
		else if (message == CLEAR)
		{
			PDBG("Clearing tasks.");
			_task_manager.clear_tasks();
			PDBG("Done.");
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
				Genode::Dataspace_capability binDsCap = _task_manager.binary_ds(name_ds.cap(), binary_size);
				Genode::Rm_session* rm = Genode::env()->rm_session();
				char* bin = (char*)rm->attach(binDsCap);
				NETCHECK_LOOP(receive_data(bin, binary_size));

				PINF("Got binary '%s' of size %d.", name_ds.local_addr<char>(), binary_size);
				rm->detach(bin);
			}
			PDBG("Done.");
		}
		else if (message == GET_LIVE)
		{
			Genode::Dataspace_capability xmlDsCap = _task_manager.live_data();
			Genode::Rm_session* rm = Genode::env()->rm_session();
			char* xml = (char*)rm->attach(xmlDsCap);

			size_t size = std::strlen(xml) + 1;
			PINF("Sending profile data of size %d", size);
			NETCHECK_LOOP(sendInt32_t(size));
			NETCHECK_LOOP(send_data(xml, size));

			rm->detach(xml);
			PDBG("Done.");
		}
		else if (message == START)
		{
			PDBG("Starting tasks.");
			_task_manager.start();
			PDBG("Done.");
		}
		else if (message == STOP)
		{
			PDBG("Stopping tasks.");
			_task_manager.stop();
			PDBG("Done.");
		}
		else if (message == GET_PROFILE)
		{
			Genode::Dataspace_capability xmlDsCap = _task_manager.profile_data();
			Genode::Rm_session* rm = Genode::env()->rm_session();
			char* xml = (char*)rm->attach(xmlDsCap);

			size_t size = std::strlen(xml) + 1;
			PINF("Sending profile data of size %d", size);
			NETCHECK_LOOP(sendInt32_t(size));
			NETCHECK_LOOP(send_data(xml, size));

			rm->detach(xml);
			PDBG("Done.");
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
