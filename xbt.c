/* xmod.c - simple example of a crash extension
 *
 # gcc -Wall -D_GNU_SOURCE -I/usr/include/crash -shared -rdynamic -o xmod.so xmod.c -fPIC -DX86_64
*/
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <ftw.h>
#include "defs.h"      /* From the crash source top-level directory */

/* Temp. Returns malloced string. */
static char *module_debuginfo_path(struct load_module *lm)
{
	const char *mod_dir_path = getenv("MODULE_PATH");
	char mod_name[PATH_MAX]; /* foo.ko */
	char *info_path = NULL;

	int ftw_cb(const char *path, const struct stat *sb, int type)
	{
		if (type != FTW_F)
			return 0;

		if (strcmp(mod_name, basename(path)) == 0) {
			info_path = strdup(path);
			return 1;
		}

		return 0;
	}

	if (mod_dir_path == NULL)
		return NULL;

	snprintf(mod_name, sizeof(mod_name), "%s.ko", lm->mod_name);
	ftw(mod_dir_path, &ftw_cb, 4);

	return info_path;
}

void xbt_func(void)
{
	struct task_context *tc = CURRENT_CONTEXT();
	struct bt_info bt_info = {
		.stackbuf = NULL,
		.tc = tc,
		.task = tc->task,
		.stackbase = GET_STACKBASE(tc->task),
		.stacktop = GET_STACKTOP(tc->task),
		.flags = BT_FULL,
	}, *bt = &bt_info;
	int level = 0;
	bool is_done = false;
	ulong rsp;
	char *rip_sym;

	// ACTIVE();
	// KDUMP_DUMPFILE();

	fprintf(fp, "# stack %#016lx %#016lx\n", bt->stackbase, bt->stacktop);

	// back_trace(bt);
	fill_stackbuf(bt);

	// get_kdump_regs(bt, &bt->instptr, &bt->stkptr); DNW
	machdep->get_stack_frame(bt, &bt->instptr, &bt->stkptr);
	fprintf(fp, "# rip %#016lx, rsp %#016lx\n",  bt->instptr, bt->stkptr);

	rsp = bt->stkptr;
	if (rsp == 0 || !accessible(rsp)) {
		error(INFO, "cannot access memory at rsp %#016lx\n", rsp);
		return;
	}

	if (!INSTACK(rsp, bt)) {
		error(INFO, "rsp %#016lx not in stack\n", rsp);
		return;
	}

	rip_sym = closest_symbol(bt->instptr);
	fprintf(fp, "# rip_sym %s\n", rip_sym);

	




	/* Assume not in estack. */
	/* Assume not in IRQ stack. */

	machdep->back_trace(bt);
	// x86_64_low_budget_back_trace_cmd(bt) // not exported.

/*
  if (module_symbol(text, NULL, &lm, NULL, 0))
  fprintf(ofp, " [%s]", lm->mod_name);
*/
}

void xmod_func(void)
{
	struct load_module *lm;
	struct mod_section_data *md;
        int i, j;

	for (i = 0; i < argcnt; i++) {
		if (!is_module_name(args[i], NULL, &lm))
			continue;

		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "text", lm->mod_text_start);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "etext", lm->mod_etext_guess);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "rodata", lm->mod_rodata_start);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "data", lm->mod_data_start);
		fprintf(fp, "%s %8s %#016lx\n", lm->mod_name, "bss", lm->mod_bss_start);

		for (j = 0; j < lm->mod_sections; j++) {
			md = &lm->mod_section_data[j];
			fprintf(fp, "# name=%s, offset=%#016lx, size=%#016lx\n",
				md->name, md->offset, md->size);
		}

		char *info_path = module_debuginfo_path(lm);
		if (info_path != NULL)
			fprintf(fp, "# %s\n", info_path);

		free(info_path);
	}



/*
  p ((struct module *) 0xffffffffa0db5440)->sect_attrs[0].attrs[0]
 p ((struct module *) 0xffffffffa0db5440)->sect_attrs[0].attrs[0]
7 = {
  mattr = {
    attr = {
      name = 0xffff88011400ab60 ".note.gnu.build-id",
      owner = 0x0,
      mode = 292
    },
    show = 0xffffffff810abed0 <module_sect_show>,
    store = 0,
    setup = 0,
    test = 0,
    free = 0
  },
  name = 0xffff88011400ab60 ".note.gnu.build-id",
  address = 18446744072113252104
*/

/*
crash> p *((struct module *) 0xffffffffa0db5440)->notes_attrs
$7 = {
dir = 0xffff8801991745c0, 
notes = 1, 
attrs = 0xffff8801021ab4d0
}
crash> p ((struct module *) 0xffffffffa0db5440)->notes_attrs->attrs
$8 = 0xffff8801021ab4d0
crash> p *((struct module *) 0xffffffffa0db5440)->notes_attrs->attrs
$9 = {
attr = {
name = 0xffff88011400ab60 ".note.gnu.build-id", 
owner = 0x0, 
mode = 292
}, 
size = 36, 
private = 0xffffffffa0da6708, 
read = 0xffffffff810ab820 <module_notes_read>, 
write = 0, 
mmap = 0
}
*/


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

static struct command_table_entry xmod_entry[] = {
	{
		.name = "xmod",
		.func = xmod_func,
		.help_data = xmod_help,
	},
	{
		.name = "xbt",
		.func = xbt_func,
		/* .help_data = xbt_help, */
	},
	{
		.name = NULL,
	},
};

void __attribute__((constructor))
xmod_init(void)
{ 
	register_extension(xmod_entry);
}

void __attribute__((destructor))
xmod_fini(void)
{
	/* Uludag GAZOZ! */
}
