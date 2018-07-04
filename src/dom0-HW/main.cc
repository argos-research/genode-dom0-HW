/* global includes */
#include <base/env.h>
#include <base/printf.h>
#include <base/rpc_server.h>
#include <base/sleep.h>
//#include <cap_session/connection.h>
#include <root/component.h>
#include <libc/component.h>
#include <dom0-HW/dom0_server.h>
#include <dom0-HW/dom0_session.h>

namespace Dom0_server
{

	struct Session_component : Genode::Rpc_object<Session>
	{

		private:

			Dom0_server *_dom0_server = nullptr;

		public:
			enum { CAP_QUOTA = 2 };
			void send_profile(Genode::String<32> task_name)
			{
				return _dom0_server->send_profile(task_name);
			}

			Session_component(Dom0_server *dom0_server)
			: Genode::Rpc_object<Session>()
			{
				_dom0_server = dom0_server;
			}
			Session_component(const Session_component&);
			Session_component& operator = (const Session_component&);

	};

	class Root_component : public Genode::Root_component<Session_component>
	{

		private:
			Genode::Env &_env;	
			Dom0_server *_dom0_server = nullptr;

		protected:

			Session_component *_create_session(const char *)
			{
				return new (md_alloc()) Session_component(_dom0_server);
			}

		public:

			Root_component(Genode::Env &env, Genode::Entrypoint &ep,
			               Genode::Allocator &allocator,
			               Dom0_server *dom0_server)
			: Genode::Root_component<Session_component>(ep, allocator), _env(env)
			{
				_dom0_server = dom0_server;
			}
			Root_component(const Root_component&);
			Root_component& operator = (const Root_component&);
	};

}

using namespace Genode;

/*
int main(int argc, char* argv[])
{
	Genode::log("dom0: Hello!\n");

	Dom0_server::Dom0_server server;

	//Cap_connection cap;

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
*/

struct Main{
	Libc::Env &_env;
	Genode::Entrypoint &_ep;
	
	Dom0_server::Dom0_server server {_env};
	
	Genode::Sliced_heap sliced_heap{_env.ram(),
	                               _env.rm()};
	                               
	Dom0_server::Root_component _dom0_server_root{_env, _ep, sliced_heap, &server};
	Main(Libc::Env &env) : _env(env), _ep(_env.ep())
	{
		_env.parent().announce(_ep.manage(_dom0_server_root));
		while (true)
		{
			// Sworn to connect and serve.
			server.connect();
			server.serve();
		}		
	}
	
	
};
//void Component::construct(Genode::Env &env) { static Main main(env); }

void Libc::Component::construct(Libc::Env &env)
{
	Libc::with_libc([&] () { static Main main(env); });
}

