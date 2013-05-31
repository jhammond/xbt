/* xbt_frame_print.c -- DWARF based frame reader/printer.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 1999-2013 Red Hat, Inc.
 * Copyright (c) 2013 Intel Corporation.
 *
 * Portions of this file are based on elfutils-0.155/src/readelf.c
 * written by by Ulrich Drepper <drepper@redhat.com>, 1999.
 *
 * Author: John L. Hammond <john.hammond@intel.com>
 */
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
#include <assert.h>
#include <limits.h>
#include "xbt.h"

/*
 * mod_debuginfo_path() -- find debuginfo for module mod_name.
 * Temporary function. Returns malloced string.
 *
 * TODO Handle build-ids.
 * TODO Interpret MODULE_PATH as a colon separated list.
 */
static char *mod_debuginfo_path(const char *mod_name) /* foo */
{
	const char *mod_dir_path = getenv("MODULE_PATH");
	char ko_name[PATH_MAX]; /* foo.ko */
	char *info_path = NULL;

	int ftw_cb(const char *path, const struct stat *sb, int type)
	{
		if (type != FTW_F)
			return 0;

		if (strcmp(ko_name, basename(path)) == 0) {
			info_path = strdup(path);
			return 1;
		}

		return 0;
	}

	if (mod_dir_path == NULL)
		return NULL;

	snprintf(ko_name, sizeof(ko_name), "%s.ko", mod_name);
	ftw(mod_dir_path, &ftw_cb, 4);

	return info_path;
}

static int xbt_dwfl_module_cb(Dwfl_Module *dwflmod,
			      void **user_data,
			      const char *name,
			      Dwarf_Addr base,
			      void *pxf)
{
	struct xbt_frame *xf = pxf;
	const char *scn_name = ".debug_info";

	int maxdies = 20;
	Dwarf_Off offset = 0;
	Dwarf_Off nextcu;
	size_t cuhl;
	Dwarf_Half version;
	Dwarf_Off abbroffset;
	uint8_t addrsize;
	uint8_t offsize;
	Dwarf_Addr cu_base;
	int level;

	Dwarf *dbg;
	Dwarf_Addr dwbias;
	Dwarf_Die *dies = NULL;

	Dwarf_Addr text_offset = xf->xf_text_offset;
	const char *path = xf->xf_mod_debuginfo_path;
	Dwarf_Addr pc;

	int rc = -1;

	xbt_trace("path '%s', text_offset %lx", path, text_offset);

	dbg = dwfl_module_getdwarf(dwflmod, &dwbias);
	if (dbg == NULL) {
		xbt_error("cannot get DWARF context descriptor: %s",
			  dwfl_errmsg (-1));
		goto out;
	}

	dies = malloc(maxdies * sizeof(dies[0]));
	if (dies == NULL) {
		xbt_error("cannot allocate DIEs: %s", strerror(errno));
		goto out;
	}

next_cu:
	if (dwarf_next_unit(dbg, offset, &nextcu, &cuhl, &version,
			    &abbroffset, &addrsize, &offsize,
			    NULL, NULL) != 0) {
		/* ... */
		rc = 0;
		goto out;
	}

	xbt_trace("CU offset %" PRIu64 ", "
		  "version %"PRIu16", "
		  "abbrev_offset %"PRIu64", "
		  "address_size %"PRIu8", "
		  "offset_size: %"PRIu8,
		  (uint64_t) offset, version, abbroffset, addrsize, offsize);

	offset += cuhl;
	level = 0;

	if (dwarf_offdie(dbg, offset, &dies[level]) == NULL) {
		xbt_error("cannot get DIE at offset %"PRIx64
			  " in section '%s': %s",
			  (uint64_t) offset, scn_name, dwarf_errmsg(-1));
		goto out;
	}

	/* Find the base address of the compilation unit.  It will
	   normally be specified by DW_AT_low_pc.  In DWARF-3 draft 4,
	   the base address could be overridden by DW_AT_entry_pc.
	   It's been removed, but GCC emits DW_AT_entry_pc and not
	   DW_AT_lowpc for compilation units with discontinuous
	   ranges.  */
	if (dwarf_lowpc(&dies[0], &cu_base) != 0) {
		Dwarf_Attribute attr_mem;

		if (dwarf_formaddr(dwarf_attr(&dies[0], DW_AT_entry_pc, &attr_mem),
				   &cu_base) != 0)
			cu_base = 0;
	}
	dwfl_module_relocate_address(dwflmod, &cu_base);

	do {
		Dwarf_Die *die;
		const char *tag_name;
		int tag;
		int c;

		offset = dwarf_dieoffset(&dies[level]);
		if (offset == ~0UL) {
			xbt_error("cannot get DIE offset: %s",
				  dwarf_errmsg(-1));
			goto out;
		}

		if (level <= 1)
			pc = -1;

		die = &dies[level];
		tag = dwarf_tag(die);
		if (tag == DW_TAG_invalid) {
			xbt_error("cannot get tag of DIE at offset %"PRIx64
				  " in section '%s': %s",
				  (uint64_t)offset, scn_name, dwarf_errmsg(-1));
			goto out;
		}

#if 0
		xbt_trace("DIE %"PRIx64" level %d, tag %d\n",
			  (uint64_t) offset, level, tag);
#endif

		if (level == 1 && tag != DW_TAG_subprogram)
			goto next_die;  /* Optimization. */

		if (tag == DW_TAG_compile_unit) {
			/* Nothing. */
		} else if (tag == DW_TAG_subprogram) {
			Dwarf_Addr low_pc = 0, high_pc = -1UL;
			Dwarf_Addr rel_low_pc;

			xbt_assert(level == 1);
			/* TODO check that crash and dwarf agree about
			 * function address. */

			dwarf_lowpc(die, &low_pc);
			if (low_pc == 0)
				goto next_die;
			rel_low_pc = low_pc;
			dwfl_module_relocate_address(dwflmod, &rel_low_pc);

			/* Adjust the passed in address rather than
			 * trying to relocate all of the DWARF
			 * addresses. Assume a constant relocation
			 * offset throughout this function. */
			pc = text_offset - (rel_low_pc - low_pc);

			dwarf_highpc(die, &high_pc);
			if (high_pc == -1UL)
				goto next_die;

			if (!(low_pc <= pc && pc < high_pc))
				goto next_die;

			xbt_trace("DIE subprogram %s, offset %lx, "
				  "pc %#lx, low_pc %#lx, high_pc %#lx",
				  dwarf_diename(die),
				  dwarf_dieoffset(die),
				  (ulong) pc, (ulong)low_pc, (ulong)high_pc);

		} else if (tag == DW_TAG_formal_parameter ||
			   tag == DW_TAG_variable) {
			Dwarf_Attribute *loc_attr, loc_attr_mem;
			int i, nr_locs;
			size_t nr_exprs = 256;
			Dwarf_Op *expr[nr_exprs];
			size_t expr_len[nr_exprs];

			/* TODO Use DW_AT_decl_file DW_AT_decl_line DW_AT_type. */

			tag_name = (tag == DW_TAG_formal_parameter) ?
				"parm" : "var";

			loc_attr = dwarf_attr(die, DW_AT_location, &loc_attr_mem);
			if (loc_attr == NULL) {
				xbt_error("%s %s, offset %lx has no location",
					  tag_name,
					  dwarf_diename(die),
					  dwarf_dieoffset(die));
				goto next_die;
			}

			nr_locs = dwarf_getlocation_addr(loc_attr, pc,
							 expr, expr_len, nr_exprs);

			xbt_trace("DIE %s %s, offset %lx, nr_locs %d",
				  tag_name,
				  dwarf_diename(die),
				  dwarf_dieoffset(die),
				  nr_locs);

			if (nr_locs < 0) {
				/* ... */
				goto next_die;
			}

			for (i = 0; i < nr_locs; i++) {
				Dwarf_Word obj[512]; /* FIXME */
				Dwarf_Word bit_mask[512];

				Dwarf_Op *op = expr[i];
				size_t len = expr_len[i];

				xbt_dwarf_eval(xf, dwarf_diename(die),
					       obj, bit_mask, sizeof(obj),
					       op, len);
				/* FIXME Break on first success. */
			}
		} else {
			goto next_die;
		}

		/* Make room for the next level's DIE.  */
		if (level + 1 == maxdies)
			dies = realloc(dies, (maxdies += 10) * sizeof(dies[0]));

		c = dwarf_child(&dies[level], &dies[level + 1]);
		if (c < 0) {
			xbt_error("cannot get next DIE: %s", dwarf_errmsg(-1));
			goto out;
		} else if (c == 0) { /* Found child. */
			level++;
		} else { /* No children. */
		next_die:
			while ((c = dwarf_siblingof(&dies[level], &dies[level])) == 1)
				if (level-- == 0)
					break;

			if (c == -1) {
				xbt_error("cannot get next DIE: %s", dwarf_errmsg(-1));
				goto out;
			}
		}
	} while (level >= 0);

	offset = nextcu;
	if (offset != 0)
		goto next_cu;
out:
	free(dies);
	xbt_trace("OUT\n");

	return DWARF_CB_OK;
}

/* FIXME Pass file to cb. */
void xbt_frame_print(FILE *file, struct xbt_frame *xf)
{
	char *mod_path = NULL;
	int mod_fd = -1;
	Dwfl *dwfl = NULL;
	int dwfl_fd = -1;

	if (xf->xf_mod_name == NULL)
		goto out;

	mod_path = xf->xf_mod_debuginfo_path = mod_debuginfo_path(xf->xf_mod_name);
	if (mod_path == NULL) {
		xbt_error("cannot find debuginfo for module '%s'",
			  xf->xf_mod_name);
		goto out;
	}

	mod_fd = open(mod_path, O_RDONLY);
	if (mod_fd < 0) {
		/* INFO? */
		xbt_error("cannot open '%s': %s",
			  mod_path, strerror(errno));
		goto out;
	}

	static const Dwfl_Callbacks dwfl_callbacks = {
		.section_address = dwfl_offline_section_address,
		/* .find_debuginfo = find_no_debuginfo, */
	};

	dwfl = dwfl_begin(&dwfl_callbacks);
	if (dwfl == NULL)
		goto out;

	dwfl_fd = dup(mod_fd);
	if (dwfl_fd < 0) {
		xbt_error("cannot dup fd %d for %s: %s",
			  mod_fd, mod_path, strerror(errno));
		goto out;
	}

	if (dwfl_report_offline(dwfl, mod_path, mod_path, dwfl_fd) == NULL) {
		xbt_error("cannot load DWARF from '%s': %s",
			  mod_path, strerror(errno)); /* XXX errno */
		close(dwfl_fd);
		dwfl_fd = -1;
		goto out;
	}
	dwfl_fd = -1;

	dwfl_report_end(dwfl, NULL, NULL);

	/* FIXME Error reporting. */
	dwfl_getmodules(dwfl, xbt_dwfl_module_cb, xf, 0 /* offset*/);
out:
	/* FIXME Cleanup. */

	if (!(dwfl_fd < 0))
		close(dwfl_fd);

	if (dwfl != NULL)
		dwfl_end(dwfl);

	if (!(mod_fd < 0))
		close(mod_fd);

}
