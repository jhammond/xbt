#ifndef _XBT_DWARF_H_
#define _XBT_DWARF_H_
#include <dwarf.h>

const char *xbt_dwarf_tag_name(unsigned int tag);
const char *xbt_dwarf_attr_name(unsigned int attr);
const char *xbt_dwarf_op_name(unsigned int op);

#endif
