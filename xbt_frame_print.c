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

static const char *xbt_dwarf_tag_name(unsigned int tag)
{
	static const char *tag_names[] = {
#define X(v) [v] = #v,
#include "DW_TAG.x"
#undef X
	};
	const char *name = NULL;

	if (tag < sizeof(tag_names) / sizeof(tag_names[0]))
		name = tag_names[tag];

	return name != NULL ? name : "-";
}

static const char *xbt_dwarf_attr_name(unsigned int attr)
{
	static const char *attr_names[] = {
#define X(v) [v] = #v,
#include "DW_AT.x"
#undef X
	};
	const char *name = NULL;

	if (attr < sizeof(attr_names) / sizeof(attr_names[0]))
		name = attr_names[attr];

	return name != NULL ? name : "-";
}

static int xbt_dwarf_attr_cb(Dwarf_Attribute *attr, void *unused)
{
	xbt_trace("ATTR %s", xbt_dwarf_attr_name(dwarf_whatattr(attr)));

	return DWARF_CB_OK;
}

int xbt_dwarf_byte_size(Dwarf_Die *die)
{
	Dwarf_Die *type_die = die, type_die_mem;
	Dwarf_Attribute *type_attr, type_attr_mem;

	while (type_die != NULL) {
		int byte_size;

		xbt_trace("DIE %s %s, offset %lx",
			  xbt_dwarf_tag_name(dwarf_tag(type_die)),
			  dwarf_diename(type_die),
			  dwarf_dieoffset(type_die));

		if (xbt_debug)
			dwarf_getattrs(type_die, &xbt_dwarf_attr_cb, NULL, 0);

		byte_size = dwarf_bytesize(type_die);
		if (!(byte_size < 0))
			return byte_size;

		type_attr = dwarf_attr_integrate(type_die, DW_AT_type, &type_attr_mem);
		if (type_attr == NULL) {
			xbt_trace("DIE %s %s, has no type attr",
				  xbt_dwarf_tag_name(dwarf_tag(type_die)),
				  dwarf_diename(type_die));
			break;
		}

		type_die = dwarf_formref_die(type_attr, &type_die_mem);
	}

	return -1;
}

/* at DW_AT_decl_file, DW_AT_call_file */
static const char *xbt_dwarf_get_file(Dwarf_Die *die, unsigned int at)
{
	Dwarf_Die *cu_die, cu_die_mem;
	/* Get the line information.  */
	Dwarf_Files *cu_files;
	size_t nr_cr_files;
	Dwarf_Attribute *file_attr, file_attr_mem;
	Dwarf_Word file_cu_index;
	const char *file = NULL;

	cu_die = dwarf_diecu(die, &cu_die_mem, NULL, NULL);
	if (cu_die == NULL)
		goto out;

	if (dwarf_getsrcfiles(cu_die, &cu_files, &nr_cr_files) < 0)
		goto out;

	file_attr = dwarf_attr_integrate(die, at, &file_attr_mem);
	if (file_attr == NULL)
		goto out;

	if (dwarf_formudata(file_attr, &file_cu_index) < 0)
		goto out;

	file = dwarf_filesrc(cu_files, file_cu_index, NULL, NULL);

out:
	return file != NULL ? file : "-";
}

/* at DW_AT_decl_line, DW_AT_call_line */
static int xbt_dwarf_get_line(Dwarf_Die *die, unsigned int at)
{
	Dwarf_Attribute *line_attr, line_attr_mem;
	Dwarf_Sword line = 0;

	line_attr = dwarf_attr_integrate(die, at, &line_attr_mem);
	if (line_attr == NULL)
		goto out;

	if (dwarf_formsdata(line_attr, &line) < 0)
		goto out;

out:
	return line;
}

/* Print a variable or formal parameter. */
static int xbt_dwarf_var_print(struct xbt_frame *xf,
			       Dwarf_Die *die, Dwarf_Addr pc)
{
	const char *tag_name = xbt_dwarf_tag_name(dwarf_tag(die));
	const char *name = dwarf_diename(die);
	Dwarf_Off offset = dwarf_dieoffset(die);
	const char *file = xbt_dwarf_get_file(die, DW_AT_decl_file);
	int line = xbt_dwarf_get_line(die, DW_AT_decl_line);

	Dwarf_Attribute *loc_attr, loc_attr_mem;
	int i, nr_locs;
	size_t nr_exprs = 256;
	Dwarf_Op *expr[nr_exprs];
	size_t expr_len[nr_exprs];
	Dwarf_Word *obj = NULL;
	Dwarf_Word *bit_mask = NULL;
	int byte_size;
	int rc = -1;

	loc_attr = dwarf_attr(die, DW_AT_location, &loc_attr_mem);
	if (loc_attr == NULL) {
		/* FIXME What's happening here? */
		xbt_trace("DIE %s %s %lx has no location",
			  tag_name, name, offset);
		goto out;
	}

	nr_locs = dwarf_getlocation_addr(loc_attr, pc,
					 expr, expr_len, nr_exprs);

	xbt_trace("DIE %s %s %lx, file %s, line %d, nr_locs %d",
		  tag_name, name, offset, file, line, nr_locs);

	if (nr_locs < 0) {
		rc = 0;
		goto out;
	}

	byte_size = xbt_dwarf_byte_size(die);
	xbt_trace("DIE %s %s %lx, byte_size %d",
		  tag_name, name, offset, byte_size);

	if (byte_size <= 0)
		goto out;

	obj = malloc(byte_size);
	if (obj == NULL) {
		xbt_error("cannot allocate %d bytes for value of '%s': %s",
			  byte_size, name, strerror(errno));
		goto out;
	}

	bit_mask = malloc(byte_size);
	if (bit_mask == NULL) {
		xbt_error("cannot allocate %d bytes for value of '%s': %s",
			  byte_size, name, strerror(errno));
		goto out;
	}

	for (i = 0; i < nr_locs; i++) {
		Dwarf_Op *op = expr[i];
		size_t op_len = expr_len[i];

		rc = xbt_dwarf_eval(xf, name, /* file, line, */
				    obj, bit_mask, byte_size, op, op_len);
		if (rc == 0)
			break;
	}

out:
	free(obj);
	free(bit_mask);

	return rc;
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
	const char *path = xf->xf_debuginfo_path;
	Dwarf_Addr abs_pc = xf->xf_rip;
	Dwarf_Addr rel_pc = 0;
	bool dwarf_pc_is_absolute;

	int rc = -1;

	/* Kernel debuginfo has absolute high/low PCs. */
	dwarf_pc_is_absolute = (xf->xf_mod == NULL);

	xbt_trace("func '%s', text_offset %lx, path '%s'",
		  xf->xf_func_name, text_offset, path);

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
		int tag;
		int c;

		offset = dwarf_dieoffset(&dies[level]);
		if (offset == ~0UL) {
			xbt_error("cannot get DIE offset: %s",
				  dwarf_errmsg(-1));
			goto out;
		}

		if (level <= 1)
			rel_pc = -1;

		die = &dies[level];
		tag = dwarf_tag(die);
		if (tag == DW_TAG_invalid) {
			xbt_error("cannot get tag of DIE at offset %"PRIx64
				  " in section '%s': %s",
				  (uint64_t)offset, scn_name, dwarf_errmsg(-1));
			goto out;
		}

#if 0
		xbt_trace("DIE %"PRIx64" level %d, tag %s\n",
			  (uint64_t)offset, level, xbt_dwarf_tag_name(tag));
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
			rel_pc = text_offset - (rel_low_pc - low_pc);

			dwarf_highpc(die, &high_pc);
			if (high_pc == -1UL)
				goto next_die;

			if (dwarf_pc_is_absolute) {
				if (!(low_pc <= abs_pc && abs_pc <= high_pc))
					goto next_die;
			} else {
				if (!(low_pc <= rel_pc && rel_pc <= high_pc))
					goto next_die;
			}

			xbt_trace("DIE subprogram %s, offset %lx, "
				  "abs_pc %#lx, rel_pc %#lx, "
				  "low_pc %#lx, high_pc %#lx",
				  dwarf_diename(die),
				  dwarf_dieoffset(die),
				  (ulong)abs_pc, (ulong)rel_pc,
				  (ulong)low_pc, (ulong)high_pc);

		} else if (tag == DW_TAG_formal_parameter ||
			   tag == DW_TAG_variable) {
			Dwarf_Addr pc = dwarf_pc_is_absolute ? abs_pc : rel_pc;

			xbt_dwarf_var_print(xf, die, pc);
		} else {
			/* Nothing. */
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

/*
 * xbt_debuginfo_path() -- find debuginfo for module mod_name.
 * Temporary function. Returns malloced string.
 *
 * TODO Handle build-ids.
 * TODO Interpret MODULE_PATH as a colon separated list.
 */
 /* mod_name NULL or foo, env_name MODULE_PATH or CRASH_MODULE_PATH */
static char *xbt_debuginfo_path(const char *mod_name, const char *env_name)
{
	const char *search_list_env = getenv(env_name);
	char *search_list = NULL;
	char *search_list_pos, *search_dir = NULL;
	char file_name[PATH_MAX]; /* vmlinux or foo.ko */
	char *info_path = NULL;

	int ftw_cb(const char *path, const struct stat *sb, int type)
	{
		if (type != FTW_F)
			return 0;

		if (strcmp(file_name, basename(path)) == 0) {
			xbt_trace("found path %s, mod_name %s, search_dir %s",
				  path,
				  mod_name != NULL ? mod_name : "NONE",
				  search_dir);
			info_path = strdup(path);
			return 1;
		}

		return 0;
	}

	if (mod_name == NULL)
		snprintf(file_name, sizeof(file_name), "vmlinux");
	else
		snprintf(file_name, sizeof(file_name), "%s.ko", mod_name);

	if (search_list_env == NULL) {
		/* FIXME */
		goto out;
	}

	search_list = strdup(search_list_env);
	if (search_list == NULL) {
		/* ... */
		goto out;
	}

	search_list_pos = search_list;
	while (info_path == NULL &&
	       (search_dir = strsep(&search_list_pos, ":")) != NULL)
		ftw(search_dir, &ftw_cb, 4);

	/* Try searching the whole thing. For Oleg. */
	if (info_path == NULL)
		ftw(search_list_env, &ftw_cb, 4);

out:
	free(search_list);

	return info_path;
}

/* FIXME Pass file to cb. */
void xbt_frame_print(FILE *file, struct xbt_frame *xf)
{
	char *path;
	int fd = -1;
	Dwfl *dwfl = NULL;
	int dwfl_fd = -1;

	path = xf->xf_debuginfo_path;
	if (path == NULL)
		path = xbt_debuginfo_path(xf->xf_mod_name, "MODULE_PATH");

	if (path == NULL)
		path = xbt_debuginfo_path(xf->xf_mod_name, "CRASH_MODULE_PATH");

	if (path == NULL) {
		xbt_error("cannot find debuginfo for module '%s'",
			  xf->xf_mod_name != NULL ? xf->xf_mod_name : "NONE");
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		/* INFO? */
		xbt_error("cannot open '%s': %s",
			  path, strerror(errno));
		goto out;
	}

	static const Dwfl_Callbacks dwfl_callbacks = {
		.section_address = dwfl_offline_section_address,
		/* .find_debuginfo = find_no_debuginfo, */
	};

	dwfl = dwfl_begin(&dwfl_callbacks);
	if (dwfl == NULL)
		goto out;

	dwfl_fd = dup(fd);
	if (dwfl_fd < 0) {
		xbt_error("cannot dup fd %d for %s: %s",
			  fd, path, strerror(errno));
		goto out;
	}

	if (dwfl_report_offline(dwfl, path, path, dwfl_fd) == NULL) {
		xbt_error("cannot load DWARF from '%s': %s",
			  path, strerror(errno)); /* XXX errno */
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

	if (!(fd < 0))
		close(fd);
}
