#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
/* #include <ftw.h> */
#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <assert.h>
#include <limits.h>
#include "xbt.h"

int xbt_debug; /* XXX */
static Dwfl *dwfl;
static LIST_HEAD(mod_cache_list);

struct mod_cache_entry {
	struct list_head mce_link;
	char mce_name[80]; /* Really 64 - sizeof(unsigned long). */
	size_t mce_section_count;
	struct {
		char mce_section_name[80];
		unsigned long mce_section_addr;
	} mce_sections[];
};

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

	xbt_trace("mod_name %s, section_count %d", lm->mod_name, section_count);

out:
	close_tmpfile();

	return section_count;
}

static int xbt_mod_get_section_name(struct load_module *lm, int i,
				    char (*name)[80])
{
	unsigned long mod = lm->module_struct;
	char gdb_cmd[256];
	int rc = -1;

	/* gdb p/x ((struct module *)0xffffffffa000eec0)->sect_attrs->attrs[1].name
	 * $21 = 0xffff880217c32dc0 ".text"
	 */

	snprintf(gdb_cmd, sizeof(gdb_cmd),
		 "p ((struct module *)%#lx)->sect_attrs->attrs[%d].name",
		 mod, i);

	xbt_trace("mod_name %s, i %d, gdb_cmd '%s'",
		  lm->mod_name, i, gdb_cmd);

	open_tmpfile();

	if (!gdb_pass_through(gdb_cmd, pc->tmpfile, GNU_RETURN_ON_ERROR)) {
err:
		xbt_error("cannot get name of section %d for module '%s'",
			  i, lm->mod_name);
		goto out;
	}

	rewind(pc->tmpfile);

	if (fscanf(pc->tmpfile, "$%*d = %*x \"%79[^\"]\"", *name) != 1)
		goto err;

	xbt_trace("mod_name %s, i %d, name '%s'",
		  lm->mod_name, i, *name);

	rc = 0;

out:
	close_tmpfile();

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

static struct mod_cache_entry *xbt_mod_cache_add(struct load_module *lm)
{
	struct mod_cache_entry *mce = NULL;
	int i, section_count;

	section_count = xbt_mod_get_section_count(lm);
	if (section_count < 0)
		goto err;

	mce = malloc(offsetof(typeof(*mce), mce_sections[section_count]));
	if (mce == NULL) {
		/* ... */
		goto err;
	}

	INIT_LIST_HEAD(&mce->mce_link);
	snprintf(mce->mce_name, sizeof(mce->mce_name), "%s", lm->mod_name);
	mce->mce_section_count = section_count;

	for (i = 0; i < section_count; i++) {
		char (*name)[80];
		unsigned long *addr;
		
		name = &mce->mce_sections[i].mce_section_name;
		addr = &mce->mce_sections[i].mce_section_addr;

		if (xbt_mod_get_section_name(lm, i, name) < 0) {
			/* ... */
			goto err;
		}

		if (xbt_mod_get_section_addr(lm, i, addr) < 0) {
			/* ... */
			goto err;
		}
	}

	list_add(&mce->mce_link, &mod_cache_list);

	return mce;

err:
	if (mce != NULL)
		list_del(&mce->mce_link);
	free(mce);

	return NULL;
}

static struct mod_cache_entry *xbt_mod_cache_lookup(const char *mod_name)
{
	struct mod_cache_entry *mce;
	struct load_module *lm;

	list_for_each_entry(mce, &mod_cache_list, mce_link) {
		if (strcmp(mod_name, mce->mce_name) == 0)
			return mce;
	}

	if (strcmp(mod_name, "kernel") == 0)
		/* TODO */;

	if (!is_module_name((char *)mod_name, NULL, &lm))
		return NULL;

	return xbt_mod_cache_add(lm);
}

static int xbt_mod_find_section_addr(const char *mod_name,
				     const char *section_name,
				     unsigned long *addr)
{
	struct mod_cache_entry *mce;
	int i;

	mce = xbt_mod_cache_lookup(mod_name);
	if (mce == NULL)
		return -1;

	for (i = 0; i < mce->mce_section_count; i++) {
		if (strcmp(section_name,
			   mce->mce_sections[i].mce_section_name) != 0)
			continue;

		*addr = mce->mce_sections[i].mce_section_addr;

		return 0;
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
	if (xbt_mod_find_section_addr(modname, secname, addr) < 0)
		*addr = -1;

	xbt_trace("modname %s, base %#lx, secname %s, shndx %"PRIu64", addr %#lx",
		  modname, base, secname, (uint64_t)shndx, *addr);

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
	}

	dwfl_report_end(dwfl, NULL, NULL);

	return rc;
}

static void xmod_func(void)
{
	xbt_debug = 1; /* XXX */

	xbt_dwfl_init();
}

static void xcu_func(void)
{
        int i;

	if (dwfl == NULL)
		return;

	for (i = 1; i < argcnt; i++) {
		/* Dwfl_Module *dwfl_mod; */
		unsigned long addr;
		Dwarf_Die *cu_die;
		Dwarf_Addr bias;

		addr = strtoul(args[i], NULL, 0);

		cu_die = dwfl_addrdie(dwfl, addr, &bias);
		if (cu_die == NULL) {
			xbt_error("unmapped address %#lx", addr);
			continue;
		}

		xbt_print("addr %#lx, cu %s, bias %#lx\n",
			  addr, dwarf_diename(cu_die), bias);
	}
}

static void xscope_func(void)
{
        int i;

	if (dwfl == NULL)
		return;

	for (i = 1; i < argcnt; i++) {
		unsigned long addr;
		Dwarf_Die *cu_die;
		Dwarf_Addr bias;
		int j, scope_count;
		Dwarf_Die *scope_dies;

		addr = strtoul(args[i], NULL, 0);

		cu_die = dwfl_addrdie(dwfl, addr, &bias);
		if (cu_die == NULL) {
			xbt_error("unmapped address %#lx", addr);
			continue;
		}

		xbt_print("addr %#lx, cu %s, bias %#lx\n",
			  addr, dwarf_diename(cu_die), bias);

		scope_count = dwarf_getscopes(cu_die, addr, &scope_dies);
		if (scope_count < 0) {
			/* ... */
			continue;
		}

		for (j = 0; j < scope_count; j++) {
			Dwarf_Die *die = &scope_dies[j];

			xbt_print("\tj %d, die %s %s\n",
				  j, xbt_dwarf_tag_name(dwarf_tag(die)),
				  dwarf_diename(die));
		}

		free(scope_dies);
	}
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
		.name = "xcu",
		.func = xcu_func,
		.help_data = xmod_help,
	},
	{
		.name = "xscope",
		.func = xscope_func,
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
