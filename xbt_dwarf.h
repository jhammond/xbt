#ifndef _XBT_DWARF_H_
#define _XBT_DWARF_H_
#include <dwarf.h>
#include "elfutils/libdw.h"

const char *xbt_dwarf_tag_name(unsigned int tag);
const char *xbt_dwarf_attr_name(unsigned int attr);
const char *xbt_dwarf_op_name(unsigned int op);
const char *xbt_dwarf_reg_name(unsigned int reg);

int xbt_dwarf_byte_size(Dwarf_Die *die);

#endif
