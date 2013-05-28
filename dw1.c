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

int main(int argc, char *argv[])
{
	char *mod_path = NULL;
	int mod_fd = -1;
	Elf *mod_elf = NULL;
	Dwarf *mod_dw = NULL;

	mod_path = argv[1];

#if 0
	fprintf(file, "### level %d, start %#016lx, end %#016lx, "
		"size %lu, *base %#016lx, "
		"text %#016lx, name %s, mod %s\n",
		fi->fi_level, fi->fi_start, fi->fi_end,
		fi->fi_end - fi->fi_start,
		*(ulong *)fi->fi_base,
		fi->fi_text,
		fi->fi_syment != NULL ? fi->fi_syment->name : "NONE",
		fi->fi_mod != NULL ? fi->fi_mod->mod_name : "NONE");

	if (fi->fi_mod == NULL)
		goto out;

	mod_path = module_debuginfo_path(fi->fi_mod);
	if (mod_path == NULL) {
		/* ... */
		goto out;
	}
#endif

	mod_fd = open(mod_path, O_RDONLY);
	if (mod_fd < 0) {
		/* INFO? */
		error(INFO, "cannot open '%s': %s\n",
		      mod_path, strerror(errno));
		goto out;
	}

#if 0
	if (elf_version(EV_CURRENT) == EV_NONE) {
		/* FATAL? */
		error(INFO, "cannot set libelf version: %s\n",
		      elf_errmsg(elf_errno()));
		goto out;
	}

	mod_elf = elf_begin(mod_fd, ELF_C_READ, NULL);
	if (mod_elf == NULL) {
		error(INFO, "error reading ELF file '%s': %s\n",
		      mod_path, elf_errmsg(elf_errno()));
		goto out;
	}

	Elf64_Ehdr *ehdr = elf64_getehdr(mod_elf);
	if (ehdr == NULL) {
		/* ... */
		goto out;
	}
#endif
#if 0
	Elf_Scn *scn = NULL;
	Elf64_Shdr *shdr;
	const char *scn_name;

	while (1) {
		scn = elf_nextscn(mod_elf, scn);
		if (scn == NULL) {
			error(INFO, "ELF file '%s' contains no '.debug_info' section\n",
			      mod_path);
			goto out;
		}

		shdr = elf64_getshdr(scn);
		scn_name = elf_strptr(mod_elf, ehdr->e_shstrndx, shdr->sh_name);

		if (strcmp(scn_name, ".debug_info") == 0)
			break;
	}

	xbt_trace("found %s %s, offset %u, size %u\n",
		  mod_path, scn_name, shdr->sh_offset, shdr->sh_size);

	Elf_Data *data = elf_getdata(scn, NULL);
	xbt_trace("data size %zu\n", data->d_size);
#endif
#if 0
	mod_dw = dwarf_begin_elf(mod_elf, DWARF_C_READ, NULL);
#endif

	mod_dw = dwarf_begin(mod_fd, DWARF_C_READ);
	if (mod_dw == NULL) {
		error(INFO, "cannot read DWARF from '%s'\n", /*...*/
		      mod_path);
		goto out;
	}

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
	if (dwarf_next_unit(mod_dw, offset, &nextcu, &cuhl, &version,
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

	if (dwarf_offdie(mod_dw, offset, &dies[level]) == NULL) {
		printf("cannot get DIE at offset %"PRIx64
		       " in section '%s': %s",
		       (uint64_t) offset, secname, dwarf_errmsg(-1));
		return 17;
	}



#define unlikely(x) (x)

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

#if 0

	Dwarf_Off off = 0;
	Dwarf_Off old_off = 0;
	size_t hdr_size;
	Dwarf_Off abbrev_offset;
	uint8_t address_size;
	uint8_t offset_size;

	while (dwarf_nextcu(mod_dw, old_off = off, &off, &hdr_size, &abbrev_offset,
			    &address_size, &offset_size) == 0) {
		xbt_trace("New CU: off = %lu, hsize = %zu, ab = %lu, "
			  "as = %"PRIu8", os = %"PRIu8"\n",
			  (unsigned long) old_off, hdr_size,
			  (unsigned long) abbrev_offset,
			  address_size,
			  offset_size);

		Dwarf_Die cu_base, *cu_die;
		cu_die = dwarf_offdie(mod_dw, old_off + hdr_size, &cu_base);
		if (cu_die == NULL) {
			/* ... */
			continue;
		}

		if (dwarf_tag(cu_die) != DW_TAG_compile_unit) {
			xbt_trace("not a compile unit\n");
			continue;
		}

		Dwarf_Die die;
		if (dwarf_child(cu_die, &die) != 0) {
			xbt_trace("no child\n");
			continue;
		}

		do {
			if (dwarf_tag(&die) != DW_TAG_subprogram)
				continue;

			xbt_trace("die offset %x\n", (unsigned) dwarf_dieoffset(&die));

			Dwarf_Addr low_pc = 0, high_pc = -1;
			dwarf_lowpc(&die, &low_pc);
			dwarf_highpc(&die, &high_pc);

			Dwarf_Attribute attr = {
				.valp = (unsigned char *) 0x424242,
			};

			// DW_AT_name
			if (dwarf_attr_integrate(&die, DW_AT_name, &attr) == NULL) {
				xbt_trace("no name\n");
			} else {
				xbt_trace("attr code %u, form %u, valp %#016lx\n",
					  attr.code, attr.form, (ulong)attr.valp);
			}

			xbt_trace("DIE %s, low_pc %#016lx, high_pc %#016lx\n",
				  dwarf_diename(&die), (ulong) low_pc, (ulong) high_pc);

		} while (dwarf_siblingof(&die, &die) == 0);
        }

#endif

out:
	if (mod_dw != NULL)
		dwarf_end(mod_dw);

	if (mod_elf != NULL)
		elf_end(mod_elf);

	if (!(mod_fd < 0))
		close(mod_fd);

	// free(mod_path);

	return 0;
}
