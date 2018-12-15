// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "main.h"
#include "config.h"
#include "elf.h"
#include "emulate.h"
#include "gdb.h"

struct ctx_t _ctx;
struct ctx_t *ctx;

static int gdb_port = -1;
static const char *elf_path = NULL;

void dump_regs(void)
{
	u32 i;

	printf("\nRegister dump:\n");
	printf(" pc:\t%08x\n", ctx->pc);
	for (i = 0; i < 128; i++)
		printf("%.3d:\t%08x %08x %08x %08x\n",
				i,
				ctx->reg[i][0],
				ctx->reg[i][1],
				ctx->reg[i][2],
				ctx->reg[i][3]
				);
}

void dump_ls(void)
{
	FILE *fp;

	printf("dumping local store to " DUMP_LS_NAME "\n");
	fp = fopen(DUMP_LS_NAME, "wb");
	fwrite(ctx->ls, LS_SIZE, 1, fp);
	fclose(fp);
}

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	perror(msg);

#ifdef FAIL_DUMP_REGS
	dump_regs();
#endif

#ifdef FAIL_DUMP_LS
	dump_ls();
#endif

	gdb_deinit();
	exit(1);
}

static void usage(void)
{
	printf("usage: anergistic [-g 1234] filename.elf\n");
	exit(1);
}

static void parse_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "g:")) != -1) {
		switch(c) {
			case 'g':
				gdb_port = strtol(optarg, NULL, 10);
				break;
			default:
				printf("Unknown argument: %c\n", c);
				usage();
		}
	}

	if (optind != argc - 1)
		usage();

	elf_path = argv[optind];
}

int main(int argc, char *argv[])
{
	u32 done;
	memset(&_ctx, 0x00, sizeof _ctx);
	ctx = &_ctx;
	parse_args(argc, argv);

#if 0
	u64 local_ptr;
	
	local_ptr = 0xdead0000dead0000ULL;
	
	ctx->reg[3][0] = (u32)(local_ptr >> 32);
	ctx->reg[3][1] = (u32)local_ptr;

	ctx->reg[4][0] = 0xdead0000;
	ctx->reg[4][1] = 0xdead0000;
#endif

	ctx->ls = malloc(LS_SIZE);
	if (ctx->ls == NULL)
		fail("Unable to allocate local storage.");
	memset(ctx->ls, 0, LS_SIZE);

#if 0
	wbe64(ctx->ls + 0x3f000, 0x100000000ULL);
	wbe32(ctx->ls + 0x3f008, 0x10000);
	wbe32(ctx->ls + 0x3e000, 0xff);
#endif

// #define FDM
#ifdef FDM
	//Set module parameters.
	//PU DMA area start address.
	//Dummy to make the module happy.
	ctx->reg[3][0] = 0xdead0000;
	ctx->reg[3][1] = 0xbeef0000;
	//PU DMA area size.
	//ctx->reg[4][0] = 0x80;
	ctx->reg[4][1] = 0x80;
	//PU EID area start address (first param).
	//Dummy to make the module happy.	
	ctx->reg[5][0] = 0xcafe0000;
	ctx->reg[5][1] = 0xbabe0000;
	//First param size.
	//ctx->reg[6][0] = 0x860;
	ctx->reg[6][1] = 0x860;
	const uint8_t fdm_indiv_seed0[] = {0x74, 0x92, 0xE5, 0x7C, 0x2C, 0x7C, 0x63, 0xF4, 0x49, 0x42, 0x26, 0x8F, 0xB4, 0x1C, 0x58, 0xED};
	const uint8_t fdm_indiv_seed1[] = {0x66, 0x83, 0x41, 0xF9, 0xC9, 0x7B, 0x29, 0x83, 0x96, 0xFA, 0x9D, 0x82, 0x07, 0x51, 0x99, 0xD8};
	const uint8_t fdm_indiv_seed2[] = {0xBC, 0x1A, 0x93, 0x4B, 0x37, 0x4F, 0xA3, 0x8D, 0x46, 0xAF, 0x94, 0xC7, 0xC3, 0x33, 0x73, 0xB3};
	const uint8_t fdm_indiv_seed3[] = {0x09, 0x57, 0x20, 0x84, 0xFE, 0x2D, 0xE3, 0x44, 0x57, 0xE0, 0xF8, 0x52, 0x7A, 0x34, 0x75, 0x3D};
	memcpy(ctx->reg[7], fdm_indiv_seed0, sizeof(fdm_indiv_seed0));
	memcpy(ctx->reg[8], fdm_indiv_seed1, sizeof(fdm_indiv_seed1));
	memcpy(ctx->reg[9], fdm_indiv_seed2, sizeof(fdm_indiv_seed2));
	memcpy(ctx->reg[10], fdm_indiv_seed3, sizeof(fdm_indiv_seed3));
#endif

#define AIM
#ifdef AIM
	//Set module parameters.
	//PU DMA area start address.
	//Dummy to make the module happy.
	ctx->reg[3][0] = 0xdead0000;
	ctx->reg[3][1] = 0xbeef0000;
	//PU DMA area size.
	//ctx->reg[4][0] = 0x80;
	ctx->reg[4][1] = 0x80;
	//PU EID area start address (first param).
	//Dummy to make the module happy.	
	ctx->reg[5][0] = 0xcafe0000;
	ctx->reg[5][1] = 0xbabe0000;
	//First param size.
	//ctx->reg[6][0] = 0x860;
	ctx->reg[6][1] = 0x860;
	const uint8_t aim_indiv_seed0[] = {0xAB, 0xCA, 0xAD, 0x17, 0x71, 0xEF, 0xAB, 0xFC, 0x2B, 0x92, 0x12, 0x76, 0xFA, 0xC2, 0x13, 0x0C};
	const uint8_t aim_indiv_seed1[] = {0x37, 0xA6, 0xBE, 0x3F, 0xEF, 0x82, 0xC7, 0x9F, 0x3B, 0xA5, 0x73, 0x3F, 0xC3, 0x5A, 0x69, 0x0B};
	const uint8_t aim_indiv_seed2[] = {0x08, 0xB3, 0x58, 0xF9, 0x70, 0xFA, 0x16, 0xA3, 0xD2, 0xFF, 0xE2, 0x29, 0x9E, 0x84, 0x1E, 0xE4};
	const uint8_t aim_indiv_seed3[] = {0xD3, 0xDB, 0x0E, 0x0C, 0x9B, 0xAE, 0xB5, 0x1B, 0xC7, 0xDF, 0xF1, 0x04, 0x67, 0x47, 0x2F, 0x85};
	memcpy(ctx->reg[7], aim_indiv_seed0, sizeof(aim_indiv_seed0));
	memcpy(ctx->reg[8], aim_indiv_seed1, sizeof(aim_indiv_seed1));
	memcpy(ctx->reg[9], aim_indiv_seed2, sizeof(aim_indiv_seed2));
	memcpy(ctx->reg[10], aim_indiv_seed3, sizeof(aim_indiv_seed3));
	u8 eid_mkey[] = {0xA6, 0x9E, 0x1B, 0xF2, 0xE8, 0xBE, 0x66, 0xC3, 0x09, 0x42, 0x0A, 0x9C, 0xFA, 0xC1, 0xC0, 0x1B, 0xA7, 0x79, 0x25, 0x58, 0xFC, 0xEF, 0x83, 0x8B, 0x38, 0xEC, 0x07, 0x6F, 0xE2, 0xAD, 0x86, 0xB9, 0x9D, 0xBB, 0x8C, 0x35, 0x98, 0xCD, 0xDA, 0xE9, 0x71, 0xB5, 0x02, 0xA4, 0xDE, 0x9D, 0x38, 0x28};
	memcpy(ctx->ls, eid_mkey, sizeof(eid_mkey));
#endif

	if (gdb_port < 0) {
		ctx->paused = 0;
	} else {
		gdb_init(gdb_port);
		ctx->paused = 1;
		gdb_signal(SIGABRT);
	}

	elf_load(elf_path);

	done = 0;

	while(done == 0) {

		if (ctx->paused == 0)
			done = emulate();

		// data watchpoints
		if (done == 2) {
			ctx->paused = 0;
			gdb_signal(SIGTRAP);
			done = 0;
		}
		
		if (done != 0) {
			printf("emulated() returned, sending SIGSEGV to gdb stub\n");
			ctx->paused = 1;
			done = gdb_signal(SIGSEGV);
		}

		if (done != 0) {
#ifdef STOP_DUMP_REGS
			dump_regs();
#endif
#ifdef STOP_DUMP_LS
			dump_ls();
#endif
		}

		if (ctx->paused == 1)
			gdb_handle_events();
	}
	printf("emulate() returned. we're done!\n");
	dump_ls();
	free(ctx->ls);
	gdb_deinit();
	return 0;
}
