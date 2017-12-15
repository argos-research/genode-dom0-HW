#pragma once

#include <base/printf.h>
#include <base/rpc_client.h>
#include <dom0-HW/dom0_session.h>

namespace Dom0_server {
struct Session_client : Genode::Rpc_client<Session>
{
	Session_client(Genode::Capability<Session> cap) :
		Genode::Rpc_client<Session>(cap) { }

	void send_profile()
	{
		call<Rpc_send_profile>();
	}
};
}
