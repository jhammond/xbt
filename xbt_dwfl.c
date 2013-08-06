#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
/* #include <fcntl.h> */
/* #include <unistd.h> */
#include <errno.h>
/* #include <malloc.h> */
/* #include <ftw.h> */
#include <bfd.h>
#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <assert.h>
#include <limits.h>
#include "xbt.h"

static Dwfl *dwfl;
int xbt_debug; /* XXX */

static int xbt_find_elf(Dwfl_Module *mod, void **userdata,
			const char *modname, Dwarf_Addr base,
			char **file_name, Elf **elfp)
{
	struct load_module *lm;
	int fd;

	xbt_trace("modname %s, base %#lx", modname, base);

	if (strcmp(modname, "kernel") == 0) {
		fd = open(pc->namelist, O_RDONLY);
		if (fd < 0)
			xbt_error("cannot open crash kernel image '%s': %s",
				  pc->namelist, strerror(errno));

		goto out;
	}

	if (!is_module_name((char *)modname, NULL, &lm))
		goto out;

	fd = open(lm->mod_namelist, O_RDONLY);
	if (fd < 0)
		xbt_error("cannot open module '%s' at '%s': %s",
			  lm->mod_name, lm->mod_namelist, strerror(errno));
	goto out;

out:
	return fd;
}

static int xbt_find_debuginfo(Dwfl_Module *mod, void **userdata,
			      const char *modname, Dwarf_Addr base,
			      const char *file_name,
			      const char *debuglink_file,
			      GElf_Word debuglink_crc,
			      char **debuginfo_file_name)
{
	struct load_module *lm;
	int fd = -1;

	xbt_trace("modname %s, base %#lx, file_name %s, "
		  "debuglink_file %s",
		  modname, base, file_name, debuglink_file);

	if (strcmp(modname, "kernel") == 0) {
		/* TODO pc->debuginfo_file */
		/* debuginfo_file is usually NULL for me. */
		fd = open(pc->namelist, O_RDONLY);
		if (fd < 0)
			xbt_error("cannot open crash kernel debuginfo '%s': %s",
				  pc->namelist, strerror(errno));
		goto out;
	}

	if (!is_module_name((char *)modname, NULL, &lm))
		goto out;

	fd = open(lm->mod_namelist, O_RDONLY);
	if (fd < 0)
		xbt_error("cannot open debuginfo for module '%s' at '%s': %s",
			  lm->mod_name, lm->mod_namelist, strerror(errno));
	goto out;

	/* TODO Try file_name, dwfl_standard_find_debuginfo() */

out:
	return fd;
}

static int xbt_mod_get_section_count(struct load_module *lm)
{
	ulong mod = lm->module_struct;
	char gdb_cmd[256];
	int section_count = -1;

	/* crash> p ((struct module *)0xffffffffa000eec0)->sect_attrs->nsections
	 * $20 = 26
	 */

	snprintf(gdb_cmd, sizeof(gdb_cmd),
		 "p/d ((struct module *)%#lx)->sect_attrs->nsections",
		 mod);

	open_tmpfile();

	if (!gdb_pass_through(gdb_cmd, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
		xbt_error("cannot get section count for module '%s'", lm->mod_name);
		goto out;
	}

	rewind(pc->tmpfile);

	if (fscanf(pc->tmpfile, "$%*d = %d", &section_count) != 1) {
		xbt_error("cannot get section count for module '%s'", lm->mod_name);
		section_count = -1;
	}
out:
	close_tmpfile();

	return section_count;
}

static int xbt_mod_get_section_name(struct load_module *lm, int i,
				    char *name, size_t name_size)
{
	ulong mod = lm->module_struct;
	char gdb_cmd[256];
	char *line = NULL;
	size_t line_size = 0;
	char *s, *t;
	int rc = -1;

	/* gdb p/x ((struct module *)0xffffffffa000eec0)->sect_attrs->attrs[1].name
	 * $21 = 0xffff880217c32dc0 ".text"
	 */

	snprintf(gdb_cmd, sizeof(gdb_cmd),
		 "p/x ((struct module *)%#lx)->sect_attrs->attrs[%d].name",
		 mod, i);

	open_tmpfile();

	if (!gdb_pass_through(gdb_cmd, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
err:
		xbt_error("cannot get name of section %d for module '%s'",
			  i, lm->mod_name);
		goto out;
	}

	rewind(pc->tmpfile);

	if (getline(&line, &line_size, pc->tmpfile) <= 0)
		goto err;

	s = line;
	strsep(&s, "\"");
	t = strsep(&s, "\"");
	if (t == NULL)
		goto err;

	xbt_trace("mod_name %s, i %d, name '%s'",
		  lm->mod_name, i, t);

	if (snprintf(name, name_size, "%s", t) >= strlen(t))
		goto err;

	rc = 0;

out:
	close_tmpfile();
	free(line);

	return rc;
}

static int xbt_mod_get_section_addr(struct load_module *lm, int i,
				    unsigned long *addr)
{
	ulong mod = lm->module_struct;
	char gdb_cmd[256];
	int rc = -1;

	/* gdb p/x ((struct module *)0xffffffffa000eec0)->sect_attrs->attrs[1].address
	 * $26 = 0xffffffffa0000000
	 */

	snprintf(gdb_cmd, sizeof(gdb_cmd),
		 "p/x ((struct module *)%#lx)->sect_attrs->attrs[%d].address",
		 mod, i);

	open_tmpfile();

	if (!gdb_pass_through(gdb_cmd, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
err:
		xbt_error("cannot get address of section %d for module '%s'",
			  i, lm->mod_name);
		goto out;
	}

	rewind(pc->tmpfile);

	if (fscanf(pc->tmpfile, "$%*d = %lx", addr) != 1)
		goto err;

	xbt_trace("mod_name %s, i %d, addr %#lx", lm->mod_name, i, *addr);

	rc = 0;
out:
	close_tmpfile();

	return rc;
}

static int xbt_mod_find_section_addr(struct load_module *lm,
				     const char *section_name,
				     unsigned long *addr)
{
	char name[256];
	int i, section_count;

	section_count = xbt_mod_get_section_count(lm);
	if (section_count < 0)
		return -1;

	for (i = 0; i < section_count; i++) {
		if (xbt_mod_get_section_name(lm, i, name, sizeof(name)) < 0)
			continue;

		if (strcmp(section_name, name) != 0)
			continue;

		return xbt_mod_get_section_addr(lm, i, addr);
	}

	return -1;
}

/* Fill *ADDR with the loaded address of the section called SECNAME in
   the given module. Use (Dwarf_Addr) -1 if this section is omitted
   from accessible memory. This is called exactly once for each
   SHF_ALLOC section that relocations affecting DWARF data refer to,
   so it can easily be used to collect state about the sections
   referenced. */
static int xbt_section_address(Dwfl_Module *mod, void **userdata,
			       const char *modname, Dwarf_Addr base,
			       const char *secname,
			       GElf_Word shndx, const GElf_Shdr *shdr,
			       Dwarf_Addr *addr)
{
	struct load_module *lm;
	unsigned long addr_tmp;

	xbt_trace("modname %s, base %#lx, secname %s, shndx %"PRIu64,
		  modname, base, secname, (uint64_t)shndx);

	*addr = -1;

	if (!is_module_name((char *)modname, NULL, &lm))
		goto out;
	
	if (xbt_mod_find_section_addr(lm, secname, &addr_tmp) < 0)
		goto out;

	*addr = addr_tmp;

out:
	return 0;
}

static Dwfl_Callbacks dwfl_callbacks = {
	.find_elf = xbt_find_elf,
	.find_debuginfo = xbt_find_debuginfo,
	.section_address = xbt_section_address,
	/* .debuginfo_path = ..., */
};

static int xbt_dwfl_init(void)
{
	Dwfl_Module *dm;
	unsigned long start, end;
	int i, rc = 0;

	if (dwfl != NULL)
		dwfl_end(dwfl);

	dwfl = dwfl_begin(&dwfl_callbacks);
	if (dwfl == NULL) {
		xbt_error("cannot start dwfl session: %s", dwfl_errmsg(-1));
		return -1;
	}

	dwfl_report_begin(dwfl);

	start = symbol_value("_text");

	if (symbol_exists("_end"))
		end = symbol_value("_end");
	else
		end = highest_bss_symbol();

	xbt_trace("kernel start %#lx, end %#lx", start, end);

	dm = dwfl_report_module(dwfl, "kernel", start, end);
	if (dm == NULL) {
		xbt_error("cannot add kernel to dwfl session: %s",
			  dwfl_errmsg(-1));
		rc = -1;
	}

	/* TODO Kernel sections. */

	/* We do not use dwfl_report_elf() since not all sections are
	 * mapped. st is crash's global symbol_table_data. */
	for (i = 0; i < st->mods_installed; i++) {
		struct load_module *lm;

                lm = &st->load_modules[i];
		start = lm->mod_base;
		end = start + lm->mod_size;

		/* Namelist is 0 length before 'mod -S' or similar is run. */

		xbt_trace("i %d, mod_name %s, mod_namelist %s, "
			  "start %#lx, end %#lx",
			  i, lm->mod_name, lm->mod_namelist, start, end);

		dm = dwfl_report_module(dwfl, lm->mod_name, start, end);
		if (dm == NULL) {
			xbt_error("cannot add module '%s' to dwfl session: %s",
				  lm->mod_name, dwfl_errmsg(-1));
			rc = -1;
		}

		if (!(lm->mod_flags & MOD_LOAD_SYMS)) {
			xbt_trace("\tsymbols not loaded");
			/* TODO Use:
			 * objfile = find_module_objfile(lm->mod_name, NULL, tree);
			 * load_module_symbols(lm->mod_name, objfile, lm->mod_base);
			 *
			 * find_module_objfile() is not exported by crash.
			 */
			continue;
		}

		int j;
		for (j = 0; j < lm->mod_sections; j++) {
			struct mod_section_data *sd;

			sd = &lm->mod_section_data[j];

			/* The offsets crash returns here are wrong. */
			xbt_trace("\tname %s, offset %#lx, size %#lx",
				  sd->name, sd->offset, sd->size);
		}
	}

	dwfl_report_end(dwfl, NULL, NULL);

	return rc;
}

void xmod_func(void)
{
	xbt_debug = 1; /* XXX */

	xbt_dwfl_init();
}

/* 
 *  The optional help data is simply an array of strings in a defined format.
 *  For example, the "help echo" command will use the help_echo[] string
 *  array below to create a help page that looks like this:
 * 
 *    NAME
 *      echo - echoes back its arguments
 *
 *    SYNOPSIS
 *      echo arg ...
 *
 *    DESCRIPTION
 *      This command simply echoes back its arguments.
 *
 *    EXAMPLE
 *      Echo back all command arguments:
 *
 *        crash> echo hello, world
 *        hello, world
 *
 */
 
char *xmod_help[] = {
	"xmod", /* command name */
	"XMOD XMOD XMOD!", /* short description */
	"arg ...", /* argument synopsis, or " " if none */
	" ...,",
	NULL,
};

static struct command_table_entry xbt_entry[] = {
	{
		.name = "xmod",
		.func = xmod_func,
		.help_data = xmod_help,
	},
	{
		.name = NULL,
	},
};

void __attribute__((constructor))
xmod_init(void)
{ 
	register_extension(xbt_entry);
}

void __attribute__((destructor))
xmod_fini(void)
{
	if (dwfl != NULL)
		dwfl_end(dwfl);
}
