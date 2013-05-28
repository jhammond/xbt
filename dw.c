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
