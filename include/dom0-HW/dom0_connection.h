#pragma once

#include <dom0-HW/dom0_client.h>
#include <base/connection.h>

namespace Dom0_server {

	struct Connection : Genode::Connection<Session>, Session_client
	{
		Connection(Genode::Env &env) :
		/* create session */
		Genode::Connection<Dom0_server::Session>(env,
							session(env.parent(),
							"ram_quota=6K, cap_quota=4")),
							Session_client(cap())
		{ }
	};


}
