/* global includes */
#include <base/env.h>
#include <base/printf.h>
#include <base/rpc_server.h>
#include <base/sleep.h>
#include <cap_session/connection.h>
#include <root/component.h>

#include <dom0-HW/dom0_server.h>
#include <dom0-HW/dom0_session.h>

namespace Dom0_server
{

	struct Session_component : Genode::Rpc_object<Session>
	{

		private:

			Dom0_server *_dom0_server = nullptr;

		public:

			void send_profile()
			{
				return _dom0_server->send_profile();
			}

			Session_component(Dom0_server *dom0_server)
			: Genode::Rpc_object<Session>()
			{
				_dom0_server = dom0_server;
			}

	};

	class Root_component : public Genode::Root_component<Session_component>
	{

		private:

			Dom0_server *_dom0_server = nullptr;

		protected:

			Session_component *_create_session(const char *args)
			{
				return new (md_alloc()) Session_component(_dom0_server);
			}

		public:

			Root_component(Genode::Rpc_entrypoint *ep,
			               Genode::Allocator *allocator,
			               Dom0_server *dom0_server)
			: Genode::Root_component<Session_component>(ep, allocator)
			{
				_dom0_server = dom0_server;
			}
	};

}

using namespace Genode;

int main(int argc, char* argv[])
{
	PDBG("dom0: Hello!\n");

	Dom0_server::Dom0_server server;

	Cap_connection cap;

	static Genode::Sliced_heap sliced_heap(env()->ram_session(),
	                               env()->rm_session());

	enum { STACK_SIZE = 4096 };
	static Rpc_entrypoint ep(&cap, STACK_SIZE, "dom0_server_ep");

	static Dom0_server::Root_component dom0_server_root(&ep, &sliced_heap, &server);
	env()->parent()->announce(ep.manage(&dom0_server_root));


	while (true)
	{
		// Sworn to connect and serve.
		server.connect();
		server.serve();
	}
}
