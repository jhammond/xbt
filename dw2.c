#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <ftw.h>
#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include "frame_info.h"
#include "list.h"

#define error(info, fmt, args...) fprintf(stderr, fmt, ##args)

#define xbt_trace(fmt, args...) \
	error(INFO, "@ %s:%d: "fmt, __func__, __LINE__, ##args)
static int
attr_callback (Dwarf_Attribute *attrp, void *arg)
{
	return DWARF_CB_OK;
}

static int dwfl_mod_cb(Dwfl_Module *dwfl_mod,
		       void **user_data,
		       const char *name,
		       Dwarf_Addr base,
		       void *arg)
{
	Dwarf_Addr dw_bias;
	Dwarf *dw = dwfl_module_getdwarf(dwfl_mod, &dw_bias);

	int maxdies = 20;
	Dwarf_Die *dies = malloc(maxdies * sizeof(dies[0]));
	Dwarf_Off offset = 0;

	/* New compilation unit.  */
	size_t cuhl;
	Dwarf_Half version;
	Dwarf_Off abbroffset;
	uint8_t addrsize;
	uint8_t offsize;
	Dwarf_Off nextcu;

next_cu:
	if (dwarf_next_unit(dw, offset, &nextcu, &cuhl, &version,
			    &abbroffset, &addrsize, &offsize,
			    NULL, NULL) != 0)
		return 13;

	printf(" Compilation unit at offset %" PRIu64 ":\n"
	       " Version: %" PRIu16 ", Abbreviation section offset: %"
	       PRIu64 ", Address size: %" PRIu8
	       ", Offset size: %" PRIu8 "\n",
	       (uint64_t) offset, version, abbroffset, addrsize, offsize);

	offset += cuhl;

	int level = 0;
	const char *secname = ".debug_info";

	if (dwarf_offdie(dw, offset, &dies[level]) == NULL) {
		printf("cannot get DIE at offset %"PRIx64
		       " in section '%s': %s",
		       (uint64_t) offset, secname, dwarf_errmsg(-1));
		return 17;
	}

	do {
		offset = dwarf_dieoffset(&dies[level]);
		if (offset == ~0ul) {
			printf("cannot get DIE offset: %s",
			       dwarf_errmsg (-1));
			goto do_return;
		}

		int tag = dwarf_tag(&dies[level]);
		if (tag == DW_TAG_invalid) {
			printf("cannot get tag of DIE at offset %" PRIx64
			       " in section '%s': %s",
			       (uint64_t) offset, secname, dwarf_errmsg(-1));
			goto do_return;
		}

		if (tag == DW_TAG_subprogram) {
			Dwarf_Die *die = &dies[level];

			Dwarf_Addr low_pc = 0, high_pc = -1;
			dwarf_lowpc(die, &low_pc);
			dwarf_highpc(die, &high_pc);

			printf("DIE %s, low_pc %#018lx, high_pc %#018lx\n",
			       dwarf_diename(die), (ulong) low_pc, (ulong) high_pc);
		}

		printf(" [%6" PRIx64 "]  %*s%d\n",
		       (uint64_t) offset, (int) (level * 2), "",
		       tag);

		dwarf_getattrs(&dies[level], attr_callback, NULL, 0);

		/* Make room for the next level's DIE.  */
		if (level + 1 == maxdies)
			dies = realloc(dies, (maxdies += 10) * sizeof(dies[0]));

		int res = dwarf_child(&dies[level], &dies[level + 1]);
		if (res > 0) {
			while ((res = dwarf_siblingof(&dies[level], &dies[level])) == 1)
				if (level-- == 0)
					break;

			if (res == -1) {
				printf("cannot get next DIE: %s\n", dwarf_errmsg (-1));
				goto do_return;
			}
		} else if (res < 0) {
			printf("cannot get next DIE: %s", dwarf_errmsg (-1));
			goto do_return;
		} else {
			level++;
		}
	} while (level >= 0);

	offset = nextcu;
	if (offset != 0)
		goto next_cu;

do_return:
	free(dies);

	return DWARF_CB_OK;
}

int main(int argc, char *argv[])
{
	char *mod_path = NULL;
	int mod_fd = -1;

	mod_path = argv[1];

	mod_fd = open(mod_path, O_RDONLY);
	if (mod_fd < 0) {
		/* INFO? */
		error(INFO, "cannot open '%s': %s\n",
		      mod_path, strerror(errno));
		goto out;
	}

	static const Dwfl_Callbacks dwfl_callbacks = {
		.section_address = dwfl_offline_section_address,
		/* .find_debuginfo = find_no_debuginfo, */
	};

	Dwfl *dwfl = dwfl_begin(&dwfl_callbacks);
	if (dwfl_report_offline(dwfl, mod_path, mod_path, mod_fd) == NULL)
		return 45;

	dwfl_report_end(dwfl, NULL, NULL);
	dwfl_getmodules(dwfl, dwfl_mod_cb, NULL, 0);
	dwfl_end(dwfl);
out:
	return 0;
}
