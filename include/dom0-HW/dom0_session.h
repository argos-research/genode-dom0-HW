#pragma once

#include <session/session.h>
#include <base/rpc.h>
#include <string>

namespace Dom0_server {

	struct Session : Genode::Session
	{
	static const char *service_name() { return "dom0"; }

	virtual void send_profile(Genode::String<32> task_name) = 0;


	/*******************
	 ** RPC interface **
	 *******************/
	GENODE_RPC(Rpc_send_profile, void, send_profile, Genode::String<32>);

	GENODE_RPC_INTERFACE(Rpc_send_profile);
};
}
