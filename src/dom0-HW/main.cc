#include <base/component.h>
#include <libc/component.h>
#include <root/component.h>
#include <base/signal.h>
#include <base/sleep.h>
#include <base/log.h>
#include <base/printf.h>
#include <dom0-HW/dom0_server.h>
#include <base/heap.h>
#include <base/service.h>
#include <dom0-HW/dom0_session.h>

namespace Dom0_server {
	struct Main;
	struct Session_component;
	struct Root_component;
}

struct Dom0_server::Session_component : Genode::Rpc_object<Session>
{
	private:
		Dom0_server* _dom0=nullptr;
	public:
		enum { CAP_QUOTA = 2 };

		void send_profile(Genode::Dataspace_capability xmlDsCap)
		{
			_dom0->send_profile(xmlDsCap);
		}

		Session_component(Dom0_server *dom0)
		: Genode::Rpc_object<Session>()
		{
			_dom0 = dom0;
		}
	Session_component(const Session_component&);
	Session_component& operator = (const Session_component&);	
};

class Dom0_server::Root_component : public Genode::Root_component<Session_component>
{
	private:
		Dom0_server* _dom0 { };
	protected:

		Session_component *_create_session(const char*)
		{
			return new (md_alloc()) Session_component(_dom0);
		}

	public:

		Root_component(Genode::Entrypoint &ep,
		               Genode::Allocator &alloc,
		               Dom0_server *dom0)
		:
			Genode::Root_component<Session_component>(ep, alloc)
		{
			_dom0=dom0;
		}
	Root_component(const Root_component&);
	Root_component& operator = (const Root_component&);	
};

struct Dom0_server::Main
{
	enum { ROOT_STACK_SIZE = 16*1024 };
	Genode::Env	&_env;
	Genode::Heap	heap	{ _env.ram(), _env.rm() };
	Dom0_server dom0{ _env };
	Root_component Dom0_root { _env.ep(), heap , &dom0};
	Main(Libc::Env &env_) : _env(env_)
	{
		_env.parent().announce(_env.ep().manage(Dom0_root));
	}
};

Genode::size_t Component::stack_size() { return 32*1024; }

void Libc::Component::construct(Libc::Env &env)
{
	Libc::with_libc([&] () { static Dom0_server::Main main(env); });
}



