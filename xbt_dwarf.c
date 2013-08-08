#include <stddef.h>
#include <dwarf.h>
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
