#pragma once

// Packet contains task descriptions as XML. uint32_t after tag indicates size in bytes.
#define SEND_DESCS 0xDE5

// Clear and stop all tasks currently managed on the server.
#define CLEAR 0xDE6

// Multiple binaries are to be sent. uint32_t after tag indicates number of binaries. Each binary packet contains another leading uint32_t indicating binary size.
#define SEND_BINARIES 0xDE5F11E

// Binary received, send next one.
#define GO_SEND 0x90

// Start queued tasks.
#define START 0x514DE5

// Stop all tasks.
#define STOP 0x514DE6

// Request profiling info as xml.
#define GET_PROFILE 0x159D1

// Request live info as xml
#define GET_LIVE 0x159D2
