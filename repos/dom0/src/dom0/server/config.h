#pragma once

#include <util/xml_node.h>

// Get XML node attribute if it exists and copy default if not.
bool attribute_value(const Genode::Xml_node& config_node, const char* type, char* dst, const char* default_val, size_t max_len);

struct Config
{
	unsigned int buf_size;
	char dhcp[4];
	char listen_address[16];
	char network_mask[16];
	char network_gateway[16];
	unsigned int port;

	static const Config& get();
};
