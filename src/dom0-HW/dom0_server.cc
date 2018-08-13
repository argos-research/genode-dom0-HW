#include <dom0-HW/dom0_server.h>

#include <cstring>
#include <vector>
#include <string>

#include <base/printf.h>

#include <lwip/genode.h>

#include <base/attached_ram_dataspace.h>
#include <base/attached_rom_dataspace.h>
#include <nic/packet_allocator.h>

#include <dom0-HW/communication_magic_numbers.h>
#include <timer_session/connection.h>
//#include <os/config.h>

/* Fiasco includes
namespace Fiasco {
#include <l4/sys/kdebug.h>
}*/

namespace Dom0_server {

Dom0_server::Dom0_server(Genode::Env &_env) :
	env(_env)
{
	lwip_tcpip_init();

	enum { BUF_SIZE = Nic::Packet_allocator::DEFAULT_PACKET_SIZE * 128 };

	Genode::Attached_rom_dataspace config(env, "config");

	Genode::Xml_node network = config.xml().sub_node("network");

	_in_addr.sin_family = AF_INET;

	/* set listen port from config */
	char port[5] = {0};
	network.attribute("port").value(port, sizeof(port));

	_in_addr.sin_port = htons(atoi(port));

	/* set listen address to any */
	_in_addr.sin_addr.s_addr = INADDR_ANY;
	
	if (network.attribute_value<bool>("dhcp", true))
	{
		
		Genode::log("DHCP network...");
		if (lwip_nic_init(0,
		                  0,
		                  0,
		                  BUF_SIZE,
		                  BUF_SIZE)) {
			PERR("lwip init failed!");
			return;
		}
	}
	else
	{
		Genode::log("manual network...");
		char ip_addr[16] = {0};
		char subnet[16] = {0};
		char gateway[16] = {0};

		network.attribute("ip-address").value(ip_addr, sizeof(ip_addr));
		network.attribute("subnet-mask").value(subnet, sizeof(subnet));
		network.attribute("default-gateway").value(gateway, sizeof(gateway));

		if (lwip_nic_init(inet_addr(ip_addr),
		                  inet_addr(subnet),
		                  inet_addr(gateway),
		                  BUF_SIZE,
		                  BUF_SIZE)) {
			PERR("lwip init failed!");
			return;
		}
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
	Genode::log("Listening...");
}

Dom0_server::~Dom0_server()
{
	disconnect();
}

int Dom0_server::connect(Genode::Env&)
{
	socklen_t len = sizeof(_target_addr);
	target_socket = lwip_accept(_listen_socket, &_target_addr, &len);
	if (target_socket < 0)
	{
		PWRN("Invalid socket from accept!");
		return target_socket;
	}
	Genode::log("Got connection");
	return target_socket;
}

// Receive data from the socket and write it into data.
ssize_t Dom0_server::receive_data(void* data, size_t size, int _target_socket)
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

// convenience function
ssize_t Dom0_server::receiveInt32_t(int32_t& data, int _target_socket)
{
	return receive_data(&data, sizeof(data), _target_socket);
}

// Send data from buffer data with size size to the socket.
ssize_t Dom0_server::send_data(void* data, size_t size, int _target_socket)
{
	ssize_t result = 0;
	ssize_t position = 0;

	// Because write() might actually write less than size bytes
	// before it returns, we call it in a loop
	// until size bytes have been written.
	do
	{
		result = lwip_write(_target_socket, (char*) data + position, size - position);
		if (result < 1)
			return -errno;
		position += result;

	} while ((size_t) position < size);

	return position;
}

// convenience function
ssize_t Dom0_server::sendInt32_t(int32_t data, int _target_socket)
{
	return send_data(&data, sizeof(data), _target_socket);
}

void Dom0_server::serve(Genode::Env& env)
{
	int message = 0;
	while (true)
	{
		NETCHECK_LOOP(receiveInt32_t(message, target_socket));
		if (message == SEND_DESCS)
		{
			Genode::log("Ready to receive task description.");

			// Get XML size.
			int xml_size;
			receiveInt32_t(xml_size, target_socket);
			Genode::Attached_ram_dataspace xml_ds(env.ram(), env.rm(), xml_size);
			Genode::log("Ready to receive XML of size ", xml_size);

			// Get XML file.
			receive_data(xml_ds.local_addr<char>(), xml_size,target_socket);
			Genode::log("Received XML. Initializing tasks.");
			_task_loader.add_tasks(xml_ds.cap());
		}
		else if (message == CLEAR)
		{
			int time_before=timer.elapsed_ms();
			_task_loader.clear_tasks();
			Genode::log("Done CLEAR. Took: %d",timer.elapsed_ms()-time_before);
		}
		else if (message == SEND_BINARIES)
		{
			Genode::log("Ready to receive binaries.");

			// Get number of binaries to receive.
			int num_binaries = 0;
			receiveInt32_t(num_binaries, target_socket);
			Genode::log(num_binaries," binaries to be sent.");

			// Receive binaries.
			for (int i = 0; i < num_binaries; i++)
			{
				// Client is waiting for ready signal.
				sendInt32_t(GO_SEND, target_socket);
				// Get binary name.
				Genode::Attached_ram_dataspace name_ds(env.ram(), env.rm(), 16);
				receive_data(name_ds.local_addr<char>(), 16, target_socket);
				// Get binary size.
				int32_t binary_size = 0;
				receiveInt32_t(binary_size, target_socket);
				// Get binary data.
				Genode::Dataspace_capability binDsCap = _task_loader.binary_ds(name_ds.cap(), binary_size);
				Genode::Region_map* rm = &env.rm();
				char* bin = (char*)rm->attach(binDsCap);
				receive_data(bin, binary_size, target_socket);
				Genode::log("Got binary");
				rm->detach(bin);
			}
		}
		else if (message == GET_LIVE)
		{
			Genode::Dataspace_capability xmlDsCap = _parser.live_data();
			Genode::Region_map* rm = &env.rm();
			char* xml = (char*)rm->attach(xmlDsCap);
			if(std::strlen(xml)>0)
			{
				size_t size = std::strlen(xml) + 1;
				Genode::log("Sending live data of size ", size);
				sendInt32_t(size, target_socket);
				send_data(xml, size, target_socket);
				rm->detach(xml);
			}
		}
		else if (message == START)
		{
			int time_before=timer.elapsed_ms();
			_task_loader.start();
			Genode::log("Done START. Took: ",timer.elapsed_ms()-time_before);
		}
		else if (message == STOP)
		{
			int time_before=timer.elapsed_ms();
			_task_loader.stop();
			Genode::log("Done STOP. Took: ",timer.elapsed_ms()-time_before);
		}
		else if (message == GET_PROFILE)
		{
			Genode::Dataspace_capability xmlDsCap = _task_loader.profile_data();
			Genode::Region_map* rm = &env.rm();
			char* xml = (char*)rm->attach(xmlDsCap);
			if(std::strlen(xml)>0)
			{
				size_t size = std::strlen(xml) + 1;
				Genode::log("Sending profile data of size ", size);
				sendInt32_t(size, target_socket);
				send_data(xml, size, target_socket);
				rm->detach(xml);
			}
		}
		else if(message == REBOOT)
		{
			//using namespace Fiasco;
                	//enter_kdebug("*#^");
		}
		else
		{
			PWRN("Unknown message: %d", message);
		}
	}
}

void Dom0_server::disconnect()
{
	lwip_close(target_socket);
	PERR("Target socket closed.");
	lwip_close(_listen_socket);
	PERR("Server socket closed.");
}


void Dom0_server::send_profile(Genode::String<32>/* task_name*/)
{
	//_controller.optimize(task_name);
	Genode::Dataspace_capability xmlDsCap = _task_loader.profile_data();
			Genode::Region_map* rm = &env.rm();
			char* xml = (char*)rm->attach(xmlDsCap);
			if(std::strlen(xml)>0)
			{
				size_t size = std::strlen(xml) + 1;
				Genode::log("Sending profile data of size ", size);
				sendInt32_t(size, target_socket);
				send_data(xml, size, target_socket);
				rm->detach(xml);
			}	
}

}
