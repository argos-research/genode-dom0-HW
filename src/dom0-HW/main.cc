#include <base/component.h>
#include <base/signal.h>
#include <base/sleep.h>
#include <base/log.h>
#include <base/printf.h>
#include "dom0_server.h"
#include <base/heap.h>
#include <base/service.h>

namespace Dom0 {
	struct Main;
}

struct Dom0::Main
{
	enum { ROOT_STACK_SIZE = 16*1024 };
	Genode::Env              &env;
	Genode::Heap              heap            { env.ram(), env.rm() };
	Genode::Service_registry  parent_services { };

	Main(Genode::Env &env_) : env(env_)
	{
		using namespace Genode;

		PDBG("dom0: Hello!\n");

		Dom0_server server(env);

		while (true)
		{
			// Sworn to connect and serve.
			server.connect();
			server.serve();
		}
	}
};

Genode::size_t Component::stack_size() { return 32*1024; }

void Component::construct(Genode::Env &env)
{
	static Dom0::Main main(env);
}
