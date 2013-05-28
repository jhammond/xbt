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
// #include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include "frame_info.h"
#include "list.h"

#define error(info, fmt, args...) fprintf(stderr, fmt, ##args)

#define xbt_trace(fmt, args...) \
	error(INFO, "@ %s:%d: "fmt, __func__, __LINE__, ##args)

#define xbt_error(fmt, args...) \
	fprintf(stderr, "@ %s:%d: "fmt, __func__, __LINE__, ##args)

static int
attr_callback (Dwarf_Attribute *attrp, void *arg)
{
	return DWARF_CB_OK;
}

struct dwfl_module_arg {
	const char *a_path;
	int a_fd;
};

#define unlikely(x) (x)

static int dwfl_module_cb(Dwfl_Module *dwflmod,
		       void **user_data,
		       const char *name,
		       Dwarf_Addr base,
		       void *parg)
{
	struct dwfl_module_arg *arg = parg;
	GElf_Addr dwflbias;
	Elf *elf = dwfl_module_getelf(dwflmod, &dwflbias);

	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr = gelf_getehdr(elf, &ehdr_mem);

	Dwarf_Die *dies = NULL;

	Elf *ebl_elf = elf; /* Was ebl->elf. */
	size_t shnum;
	size_t phnum;

	int rc = -1;

	xbt_trace("path '%s'\n", arg->a_path);
	xbt_trace("dwflbias %lx\n", (unsigned long) dwflbias);

	if (ehdr == NULL) {
/* elf_error: */
		xbt_error("cannot read ELF header from '%s': %s\n", 
			  arg->a_path, elf_errmsg(-1)); /* elf_errno()? */
		goto out;
	}

#if 0
	Ebl *ebl = ebl_openbackend(elf); /* Do we need this? */
	if (unlikely(ebl == NULL)) {
/* ebl_error: */
		xbt_error("cannot create EBL handle\n");
		goto out;
	}
#endif

	/* Determine the number of sections.  */
	if (unlikely(elf_getshdrnum (ebl_elf, &shnum) < 0)) {
		xbt_error("cannot determine number of sections: %s\n", 
			  elf_errmsg(-1));
		goto out;
	}

	xbt_trace("shnum %zu\n", shnum);

	/* Determine the number of phdrs.  */
	if (unlikely (elf_getphdrnum (ebl_elf, &phnum) < 0)) {
		xbt_error("cannot determine number of program headers: %s\n",
			  elf_errmsg (-1));
		goto out;
	}

	xbt_trace("phnum %zu\n", phnum);

	/* Before we start the real work get a debug context descriptor.  */
	Dwarf_Addr dwbias;
	Dwarf *dbg = dwfl_module_getdwarf(dwflmod, &dwbias);

	xbt_trace("dwbias %lx\n", (unsigned long) dwbias);

#if 0
	Dwarf dummy_dbg = {
		.elf = ebl_elf,
		.other_byte_order = MY_ELFDATA != ehdr->e_ident[EI_DATA]
	};
#endif
	if (dbg == NULL) {
		xbt_error("cannot get DWARF context descriptor: %s\n",
			  dwfl_errmsg (-1));
		goto out;
	}

	/* Get the section header string table index.  */
	size_t shstrndx;
	if (unlikely (elf_getshdrstrndx(ebl_elf, &shstrndx) < 0)) {
		xbt_error("cannot get section header string table index\n");
		/* why? */
		goto out;
	}

	Elf_Scn *scn = NULL;
	const char *scn_name;

	while ((scn = elf_nextscn(ebl_elf, scn)) != NULL) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);

		// if (shdr == NULL || shdr->sh_type != SHT_PROGBITS)
		// 	continue;

		scn_name = elf_strptr(ebl_elf, shstrndx, shdr->sh_name);
		xbt_trace("scn_name %s\n", scn_name);

		if (strcmp(scn_name, ".debug_info") == 0)
			break;
	}

	if (scn == NULL) {
		xbt_error("cannot find '.debug_info' section in '%s'\n",
			  arg->a_path);
		goto out;
	}

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

	dies = malloc(maxdies * sizeof(dies[0]));

next_cu:
	if (dwarf_next_unit(dbg, offset, &nextcu, &cuhl, &version,
			    &abbroffset, &addrsize, &offsize,
			    NULL, NULL) != 0) {
		/* ... */
		rc = 0;
		goto out;
	}

	printf(" Compilation unit at offset %" PRIu64 ":\n"
	       " Version: %"PRIu16", "
	       "Abbreviation section offset: %"PRIu64", "
	       "Address size: %"PRIu8", "
	       "Offset size: %"PRIu8 "\n",
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
	if (unlikely(dwarf_lowpc(&dies[0], &cu_base) != 0)) {
		Dwarf_Attribute attr_mem;

		if (dwarf_formaddr(dwarf_attr(&dies[0], DW_AT_entry_pc, &attr_mem),
				   &cu_base) != 0)
			cu_base = 0;
	}

	xbt_trace("cu_base %lx\n", (unsigned long) cu_base);

	do {
		offset = dwarf_dieoffset(&dies[level]);
		if (offset == ~0UL) {
			xbt_error("cannot get DIE offset: %s",
				  dwarf_errmsg(-1));
			goto out;
		}

		int tag = dwarf_tag(&dies[level]);
		if (tag == DW_TAG_invalid) {
			printf("cannot get tag of DIE at offset %" PRIx64
			       " in section '%s': %s",
			       (uint64_t) offset, scn_name, dwarf_errmsg(-1));
			goto out;
		}

		if (tag == DW_TAG_subprogram) {
			Dwarf_Die *die = &dies[level];

			Dwarf_Addr low_pc = 0, high_pc = -1;
			dwarf_lowpc(die, &low_pc);
			dwfl_module_relocate_address(dwflmod, &low_pc);

			dwarf_highpc(die, &high_pc);
			dwfl_module_relocate_address(dwflmod, &high_pc);

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
				goto out;
			}
		} else if (res < 0) {
			printf("cannot get next DIE: %s", dwarf_errmsg (-1));
			goto out;
		} else {
			level++;
		}
	} while (level >= 0);

	offset = nextcu;
	if (offset != 0)
		goto next_cu;

out:
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

	int dwfl_fd = dup(mod_fd);
	if (dwfl_fd < 0) {
		error(INFO, "cannot dup fd %d, '%s': %s\n",
		      mod_fd, mod_path, strerror(errno));
		goto out;
	}

	if (dwfl_report_offline(dwfl, mod_path, mod_path, dwfl_fd) == NULL) {
		close(dwfl_fd);
		goto out; /* ... */
	}

	dwfl_report_end(dwfl, NULL, NULL);

	struct dwfl_module_arg arg = {
		.a_path = mod_path,
		.a_fd = mod_fd,
	};

	dwfl_getmodules(dwfl, dwfl_module_cb, &arg, 0 /* offset*/);
	dwfl_end(dwfl);
out:
	return 0;
}
