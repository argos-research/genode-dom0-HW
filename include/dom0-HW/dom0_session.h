#pragma once

#include <session/session.h>
#include <base/rpc.h>
#include <util/string.h>

namespace Dom0_server {

	struct Session : Genode::Session
	{
	static const char *service_name() { return "dom0"; }

	virtual void send_profile(Genode::Dataspace_capability xmlDsCap) = 0;


	/*******************
	 ** RPC interface **
	 *******************/
	GENODE_RPC(Rpc_send_profile, void, send_profile, Genode::Dataspace_capability);

	GENODE_RPC_INTERFACE(Rpc_send_profile);
};
}
