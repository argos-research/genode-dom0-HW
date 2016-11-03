#include "config.h"

#include <os/config.h>
#include <nic/packet_allocator.h>
#include <cstring>

bool attribute_value(const Genode::Xml_node& node, const char* type, char* dst, const char* default_val, size_t max_len)
{
	if (node.has_attribute(type))
	{
		node.attribute(type).value(dst, max_len);
		return true;
	}
	else
	{
		std::strcpy(dst, default_val);
	}
	return false;
}


// Set defaults and overwrite if XML entries are found in the run config.
Config load_config()
{
	Config config;

	const Genode::Xml_node& config_node = Genode::config()->xml_node();
	const Genode::Xml_node& server_node = config_node.sub_node("server");

	config.buf_size = server_node.attribute_value<unsigned int>("buf-size", Nic::Packet_allocator::DEFAULT_PACKET_SIZE * 128);
	attribute_value(server_node, "dhcp", config.dhcp, "no", 4);
	attribute_value(server_node, "listen-address", config.listen_address, "0.0.0.0", 16);
	attribute_value(server_node, "network-mask", config.network_mask, "255.255.255.0", 16);
	attribute_value(server_node, "network-gateway", config.network_gateway, "192.168.217.1", 16);
	config.port = server_node.attribute_value<unsigned int>("port", 3001);

	// Print config
	PINF("Config readouts:\n");
	PINF("\tBuffer size: %d\n", config.buf_size);
	PINF("\tUse DHCP: %s\n", config.dhcp);
	PINF("\tListening address: %s\n", config.listen_address);
	PINF("\tNetwork mask: %s\n", config.network_mask);
	PINF("\tNetwork gateway: %s\n", config.network_gateway);
	PINF("\tPort: %d\n", config.port);

	return config;
}


// Get _the_ config.
const Config& Config::get()
{
	static Config config = {0};
	static bool loaded = false;

	if (!loaded)
	{
		config = load_config();
		loaded = true;
	}
	return config;
}
