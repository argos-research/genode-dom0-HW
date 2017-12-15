#pragma once

#include <dom0-HW/dom0_client.h>
#include <base/connection.h>

namespace Dom0_server {

	struct Connection : Genode::Connection<Session>, Session_client
	{
		Connection() : Genode::Connection<Session>(session("dom0_server, ram_quota=4096")),
		               Session_client(cap()) { }
	};


}
