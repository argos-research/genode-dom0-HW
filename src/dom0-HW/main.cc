#include <base/printf.h>
#include "dom0_server.h"

int main(int argc, char* argv[])
{
	PDBG("dom0: Hello!\n");

	Dom0_server server;

	while (true)
	{
		// Sworn to connect and serve.
		server.connect();
		server.serve();
	}
}
