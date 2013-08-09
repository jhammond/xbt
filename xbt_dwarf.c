#include <stddef.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include "xbt_dwarf.h"

const char *xbt_dwarf_tag_name(unsigned int tag)
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

const char *xbt_dwarf_attr_name(unsigned int attr)
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

const char *xbt_dwarf_op_name(unsigned int op)
{
	static const char *op_names[] = {
#define X(v) [v] = #v,
#include "DW_OP.x"
#undef X
	};
	const char *name = NULL;

	if (op < sizeof(op_names) / sizeof(op_names[0]))
		name = op_names[op];

	return name != NULL ? name : "-";
}

const char *xbt_dwarf_reg_name(unsigned int reg)
{
	static const char *reg_names[] = {
		[0] = "rax",
		[1] = "rdx",
		[2] = "rcx",
		[3] = "rbx",
		[4] = "rsi",
		[5] = "rdi",
		[6] = "rbp",
		[7] = "rsp",
		[8] = "r8",
		[9] = "r9",
		[10] = "r10",
		[11] = "r11",
		[12] = "r12",
		[13] = "r13",
		[14] = "r14",
		[15] = "r15",
		[16] = "ra",
	};
	const char *name = NULL;

	if (reg < sizeof(reg_names) / sizeof(reg_names[0]))
		name = reg_names[reg];

	return name != NULL ? name : "-";
}

int xbt_dwarf_byte_size(Dwarf_Die *die)
{
	Dwarf_Die *type_die = die, type_die_mem;
	Dwarf_Attribute *type_attr, type_attr_mem;

	while (type_die != NULL) {
		int byte_size;

#if 0
		xbt_trace("DIE %s %s, offset %lx",
			  xbt_dwarf_tag_name(dwarf_tag(type_die)),
			  dwarf_diename(type_die),
			  dwarf_dieoffset(type_die));
#endif

		byte_size = dwarf_bytesize(type_die);
		if (!(byte_size < 0))
			return byte_size;

		type_attr = dwarf_attr_integrate(type_die, DW_AT_type, &type_attr_mem);
		if (type_attr == NULL) {
#if 0
			xbt_trace("DIE %s %s, has no type attr",
				  xbt_dwarf_tag_name(dwarf_tag(type_die)),
				  dwarf_diename(type_die));
#endif
			break;
		}

		type_die = dwarf_formref_die(type_attr, &type_die_mem);
	}

	return -1;
}

