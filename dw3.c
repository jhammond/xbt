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
#include <elfutils/libdwfl.h>
#include <assert.h>
#include "frame_info.h"
#include "list.h"

#ifndef ARRAY_LENGTH
#define ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define xbt_trace(fmt, args...) \
	frpintf(stderr, "@ %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#define xbt_error(fmt, args...) \
	fprintf(stderr, "@ %s:%d: "fmt"\n", __func__, __LINE__, ##args)

#define xbt_assert(x) (assert(x))

#define unlikely(x) (x)

#if 0
static int attr_callback(Dwarf_Attribute *attrp, void *arg)
{
	return DWARF_CB_OK;
}
#endif

struct xbt_dwfl_module_arg {
	const char *a_path;
	unsigned long a_text; /* Start of module .text section. */
	unsigned long a_text_offset; /* Offset of saved RIP in .text. */
};

enum {
	XBT_EVAL_OK,
	XBT_EVAL_UNDERFLOW,
	XBT_EVAL_OVERFLOW,
	XBT_EVAL_BAD_OP,
	XBT_EVAL_DIV_ERR,
	XBT_EVAL_MEM_ERR,
	XBT_EVAL_UNSUPP,
	XBT_EVAL_TODO,
};

static bool xbt_eval_abort_on_error = true;

#define DWARF_SWORD_MIN LONG_MIN /* XXX? */

#define XBT_NR_REGS 16

static int xbt_eval(struct xbt_dwfl_module_arg *arg,
		    Dwarf_Word *result, size_t *result_size,
		    bool *result_is_value, /* Signedness? */
		    const Dwarf_Op *expr, size_t expr_len)
{
	Dwarf_Word s[256];
	size_t k = 0;
	int rc;

	*result = 0x4242424242424242UL;
	*result_size = sizeof(*result);
	*result_is_value = false;

#define OUT(err)						\
	do  {							\
		int _err = (err);				\
		assert(0 <= _err);				\
		if (xbt_eval_abort_on_error && _err != 0)	\
			abort();				\
		rc = -_err;					\
		goto out;					\
	} while (0)

#define REQUIRE(cond, err)			\
	do {					\
		if (!(cond))			\
			OUT(err);		\
	} while (0)

#define PUSH(v)								\
	do {								\
		REQUIRE(k < ARRAY_LENGTH(s) - 1, XBT_EVAL_OVERFLOW);	\
		s[k++] = (v);						\
	} while (0)

#define POP()						\
	({						\
		REQUIRE(0 < k, XBT_EVAL_UNDERFLOW);	\
		s[--k];					\
	})

#define PEEK(d)							\
	({							\
		size_t _d = (d);				\
								\
		REQUIRE(_d < k, XBT_EVAL_UNDERFLOW);		\
		s[k - _d - 1];					\
	})

#define MEM(m, size)				\
	({					\
		OUT(XBT_EVAL_TODO);		\
		0;				\
	})

#define REG(r)					\
	({					\
		OUT(XBT_EVAL_TODO);		\
		0;				\
	})

/* XXX */
#define REG_LOC(r)						\
	do {							\
		Dwarf_Word _r = (r);				\
								\
		REQUIRE(_r < XBT_NR_REGS, XBT_EVAL_BAD_OP);	\
		PUSH(_r);					\
	} while (0)

	size_t i = 0;
	/* Due to skip, i is also modified in the loop body. */
	for (i = 0; i < expr_len; i++) {
		uint8_t u = expr[i].unit;
		Dwarf_Word n0 = expr[i].number;
		Dwarf_Word n1 = expr[i].number2;
		
		switch (u) {
		/* Literal encodings. */
		case DW_OP_lit0 ... DW_OP_lit31:
			PUSH(u - DW_OP_lit0);
			break;
		case DW_OP_addr:
			PUSH(n0);
			break;
		case DW_OP_const1u:
		case DW_OP_const1s:
		case DW_OP_const2u:
		case DW_OP_const2s:
		case DW_OP_const4u:
		case DW_OP_const4s:
		case DW_OP_const8u:
		case DW_OP_const8s:
		case DW_OP_constu:
		case DW_OP_consts:
			PUSH(n0);
			break;

		/* Register based addressing. */
		case DW_OP_fbreg: {
			Dwarf_Word b;

			b = FRAME_BASE();
			PUSH(b + n0);
			break;
		}
		case DW_OP_breg0 ... DW_OP_breg31:
			PUSH(REG(u - DW_OP_breg0) + n0);
			break;
		case DW_OP_bregx:
			PUSH(REG(n0) + n1);
			break;

		/* Stack operations. */
		case DW_OP_dup:
			PUSH(PEEK(0));
			break;
		case DW_OP_drop:
			(void) POP();
			break;
		case DW_OP_over:
			PUSH(PEEK(1));
			break;
		case DW_OP_pick:
			PUSH(PEEK(n0));
			break;
		case DW_OP_swap: {
			Dwarf_Word t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t0);
			PUSH(t1);
			break;
		}
		case DW_OP_rot: {
			Dwarf_Word t0, t1, t2;

			t0 = POP();
			t1 = POP();
			t2 = POP();
			PUSH(t0);
			PUSH(t2);
			PUSH(t1);
			break;
		}

		/* Dereference operations. */
		case DW_OP_deref: {
			Dwarf_Word t0;

			t0 = POP();
			PUSH(MEM(t0, sizeof(t0)));
			break;
		}
		case DW_OP_deref_size: {
			Dwarf_Word t0;

			t0 = POP();
			PUSH(MEM(t0, n0));
			break;
		}
		case DW_OP_xderef:
			/* Extended dereference: t0 is address, t1 is
			 * address space identifier. */
			OUT(XBT_ERR_UNSUPP); /* Not emitted AFAIK. */
		case DW_OP_xderef_size:
			/* Same as xderef excpet that n0 is the value size. */
			OUT(XBT_ERR_UNSUPP); /* Not emitted AFAIK. */
		case DW_OP_push_object_address:
			/* For 'this'? */
			OUT(XBT_ERR_UNSUPP); /* Not emitted AFAIK. */
		case DW_OP_form_tls_address:
			OUT(XBT_ERR_TODO); /* Not emitted AFAIK. */
		case DW_OP_call_frame_cfa:
			/* CFA computed from CFI. */
			OUT(XBT_ERR_TODO); /* Not emitted AFAIK. */

		/* Arithmetic and logical operations. */
		case DW_OP_abs: {
			Dwarf_Word t0;

			t0 = POP();
			if ((Dwarf_Sword) t0 < 0)
				t0 = -t0;
			PUSH(t0);
			break;
		}
		case DW_OP_and: {
			Dwarf_Word t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t0 & t1);
			break;
		}
		case DW_OP_div: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			/* TODO CHECKME */
			REQUIRE(t0 != 0 && (t0 != -1 || t1 != DWARF_SWORD_MIN),
				XBT_EVAL_DIV_ERR);
			PUSH(t1 / t0);
			break;
		}
		case DW_OP_minus: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 - t0);
			break;
		}
		case DW_OP_mod: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			/* TODO CHECKME */
			REQUIRE(t0 != 0 && (t0 != -1 || t1 != DWARF_SWORD_MIN),
				XBT_EVAL_DIV_ERR);
			PUSH(t1 % t0);
			break;
		}
		case DW_OP_mul: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 * t0);
			break;
		}
		case DW_OP_neg: {
			Dwarf_Sword t0;

			t0 = POP();
			PUSH(-t0);
			break;
		}
		case DW_OP_not: {
			Dwarf_Word t0;

			t0 = POP();
			PUSH(~t0);
			break;
		}
		case DW_OP_or: {
			Dwarf_Word t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t0 | t1);
			break;
		}
		case DW_OP_plus: {
			Dwarf_Word t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t0 + t1);
			break;
		}
		case DW_OP_plus_uconst: {
			Dwarf_Word t0;

			t0 = POP();
			PUSH(t0 + n0);
			break;
		}
		case DW_OP_shl: {
			Dwarf_Word t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 << t0); /* XXX? */
			break;
		}
		case DW_OP_shr: {
			Dwarf_Word t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 >> t0); /* XXX? */
			break;
		}
		case DW_OP_shra: {
			Dwarf_Word t0;
			Dwarf_Sword t1; /* XXX? */

			t0 = POP();
			t1 = POP();
			PUSH(t1 >> t0);
			break;
		}
		case DW_OP_xor: {
			Dwarf_Word t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 ^ t0);
			break;
		}

		/* Control flow operations. */
		case DW_OP_eq: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 == t0);
			break;
		}
		case DW_OP_ge: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 >= t0);
			break;
		}
		case DW_OP_gt: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 > t0);
			break;
		}
		case DW_OP_le: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 <= t0);
			break;
		}
		case DW_OP_lt: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 < t0);
			break;
		}
		case DW_OP_ne: {
			Dwarf_Sword t0, t1;

			t0 = POP();
			t1 = POP();
			PUSH(t1 != t0);
			break;
		}
		case DW_OP_skip: do_skip: {
			Dwarf_Word off;
			size_t j;

			/* CHECKME */
			off = expr[i].offset + 3 + (int16_t)n0;
			for (j = 0; j < expr_len; j++)
				if (expr[j].offset == off)
					break;

			if (j == expr_len)
				OUT(XBT_EVAL_BAD_OP);

			i = j - 1;
			break;
		}
		case DW_OP_bra: {
			Dwarf_Word t0;

			t0 = POP();
			if (t0 != 0)
				goto do_skip;
			break;
		}
		case DW_OP_call2:
		case DW_OP_call4:
		case DW_OP_call_ref:
			OUT(XBT_ERR_UNSUPP); /* Not emitted AFAIK. */

		/* Special operations. */
		case DW_OP_nop:
			break;

		/* Register locations. */	
		case DW_OP_reg0 ... DW_OP_reg31:
			/* These operations name a register location. */
			PUSH(REG_LOC(u - DW_OP_reg0));
			break;
		case DW_OP_regx
			/* This operation names a register location. */
			PUSH(REG_LOC(n0));
			break;

		/* Implicit locations. */
		case DW_OP_implicit_value:
		/* The DW_OP_implicit_value operation specifies an
		   immediate value using two operands: an unsigned
		   LEB128 length, followed by a block representing the
		   value in the memory representation of the target
		   machine. The length operand gives the length in
		   bytes of the block. */
			OUT(XBT_ERR_TODO) /* Not emitted AFAIK. */

		case DW_OP_stack_value: {
			/* FIXME this is wrong for composite locations. */
			*val = POP();
			rc = 0;
			goto out;
		}

		/* Empty location descriptions.
		   An empty location description consists of a DWARF
		   expression containing no operations. It represents
		   a piece or all of an object that is present in the
		   source but not in the object code (perhaps due to
		   optimization). */

		/* Composite location descriptions. */
		case DW_OP_piece:
		case DW_OP_bit_piece:
			OUT(XBT_EVAL_TODO); /* Rarely emimtted. */

		/* GNU extensions. */
		case DW_OP_GNU_push_tls_address:
		case DW_OP_GNU_uninit:
		case DW_OP_GNU_encoded_addr:
		case DW_OP_GNU_implicit_pointer:
			OUT(XBT_EVAL_UNSUPP); /* Not emitted AFAIK. */

		default:
			OUT(XBT_EVAL_BAD_OP);
		}
	}

out:
	return rc;
}

static int xbt_dwfl_module_cb(Dwfl_Module *dwflmod,
			      void **user_data,
			      const char *name,
			      Dwarf_Addr base,
			      void *parg)
{
	struct xbt_dwfl_module_arg *arg = parg;
	const char *scn_name = ".debug_info";

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

	Dwarf *dbg;
	Dwarf_Addr dwbias;
	Dwarf_Die *dies = NULL;

	Dwarf_Addr text_offset = arg->a_text_offset;
	Dwarf_Addr pc; /* Bah! */

	int rc = -1;

	xbt_trace("path '%s', text_offset %lx", arg->a_path, text_offset);

	dbg = dwfl_module_getdwarf(dwflmod, &dwbias);
	if (dbg == NULL) {
		xbt_error("cannot get DWARF context descriptor: %s",
			  dwfl_errmsg (-1));
		goto out;
	}
	xbt_trace("dwbias %lx\n", (unsigned long) dwbias);

	dies = malloc(maxdies * sizeof(dies[0]));
	if (dies == NULL) {
		xbt_error("cannot allocate DIEs: %s", strerror(errno));
		goto out;
	}

next_cu:
	if (dwarf_next_unit(dbg, offset, &nextcu, &cuhl, &version,
			    &abbroffset, &addrsize, &offsize,
			    NULL, NULL) != 0) {
		/* ... */
		rc = 0;
		goto out;
	}

	xbt_trace("CU offset %" PRIu64 ", "
		  "version %"PRIu16", "
		  "abbrev_offset %"PRIu64", "
		  "address_size %"PRIu8", "
		  "offset_size: %"PRIu8"",
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
	dwfl_module_relocate_address(dwflmod, &cu_base);
	xbt_trace("cu_base %lx", (ulong)cu_base);

	do {
		Dwarf_Die *die;
		const char *tag_name;
		int tag;
		int c;

		offset = dwarf_dieoffset(&dies[level]);
		if (offset == ~0UL) {
			xbt_error("cannot get DIE offset: %s",
				  dwarf_errmsg(-1));
			goto out;
		}

		if (level <= 1)
			pc = -1;

		die = &dies[level];
		tag = dwarf_tag(die);
		if (tag == DW_TAG_invalid) {
			xbt_error("cannot get tag of DIE at offset %"PRIx64
				  " in section '%s': %s",
				  (uint64_t) offset, scn_name, dwarf_errmsg(-1));
			goto out;
		}

		if (level == 1 && tag != DW_TAG_subprogram)
			goto next_die;  /* Optimization. */

		if (tag == DW_TAG_compile_unit) {
			/* Nothing. */
		} else if (tag == DW_TAG_subprogram) {
			Dwarf_Addr low_pc = 0, high_pc = -1UL;
			Dwarf_Addr rel_low_pc;

			xbt_assert(level == 1);
			/* TODO check that crash and dwarf agree about
			 * function address. */

			dwarf_lowpc(die, &low_pc);
			if (low_pc == 0)
				goto next_die;
			rel_low_pc = low_pc;
			dwfl_module_relocate_address(dwflmod, &rel_low_pc);

			/* Adjust the passed in address rather than
			 * trying to relocate all of the DWARF
			 * addresses. Assume a constant relocation
			 * offset throughout this function. */
			pc = text_offset - (rel_low_pc - low_pc);

			dwarf_highpc(die, &high_pc);
			if (high_pc == -1UL)
				goto next_die;

			if (!(low_pc <= pc && pc < high_pc))
				goto next_die;

			printf("DIE subprogam %s, offset %lx, "
			       "pc %#lx, low_pc %#lx, high_pc %#lx",
			       dwarf_diename(die),
			       dwarf_dieoffset(die),
			       (ulong) pc, (ulong)low_pc, (ulong)high_pc);

		} else if (tag == DW_TAG_formal_parameter ||
			   tag == DW_TAG_variable) {
			Dwarf_Attribute *loc_attr, loc_attr_mem;
			int i, nr_locs;
			size_t nr_exprs = 256;
			Dwarf_Op *expr[nr_exprs];
			size_t expr_len[nr_exprs];

			tag_name = (tag == DW_TAG_formal_parameter) ?
				"parm" : "var";

			loc_attr = dwarf_attr(die, DW_AT_location, &loc_attr_mem);
			if (loc_attr == NULL) {
				xbt_error("%s %s, offset %lx\n has no location",
					  tag_name,
					  dwarf_diename(die),
					  dwarf_dieoffset(die));
				goto next_die;
			}

			nr_locs = dwarf_getlocation_addr(loc_attr, pc,
							 expr, expr_len, nr_exprs);

			printf("DIE %s %s, offset %lx, nr_locs %d\n",
			       tag_name,
			       dwarf_diename(die),
			       dwarf_dieoffset(die),
			       nr_locs);
			// DW_AT_decl_file DW_AT_decl_line DW_AT_type

			if (nr_locs < 0) {
				/* ... */
				goto next_die;
			}

			for (i = 0; i < nr_locs; i++) {
				Dwarf_Op *op = expr[i];
				size_t j, len = expr_len[i];

				for (j = 0; j < len; j++)
					printf("%02hhx%s",
					       op[j].atom, j < len - 1 ? " " : "\n");
			}
		} else {
			goto next_die;
		}

		printf(" [%6"PRIx64"]  %*s%d\n",
		       (uint64_t) offset, (int) (level * 2), "", tag);

#if 0
		dwarf_getattrs(&dies[level], attr_callback, NULL, 0);
#endif
		/* Make room for the next level's DIE.  */
		if (level + 1 == maxdies)
			dies = realloc(dies, (maxdies += 10) * sizeof(dies[0]));

		c = dwarf_child(&dies[level], &dies[level + 1]);
		if (c < 0) {
			xbt_error("cannot get next DIE: %s", dwarf_errmsg(-1));
			goto out;
		} else if (c == 0) {
			/* Found child. */
			level++;
		} else {
			/* No children. */
		next_die:
			while ((c = dwarf_siblingof(&dies[level], &dies[level])) == 1)
				if (level-- == 0)
					break;
			if (c == -1) {
				xbt_error("cannot get next DIE: %s", dwarf_errmsg(-1));
				goto out;
			}
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
	unsigned long text;
	unsigned long addr;

	mod_path = argv[1];
	text = strtoul(argv[2], NULL, 0);
	addr = strtoul(argv[3], NULL, 0);

	mod_fd = open(mod_path, O_RDONLY);
	if (mod_fd < 0) {
		/* INFO? */
		xbt_error("cannot open '%s': %s",
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
		xbt_error("cannot dup fd %d, '%s': %s",
			  mod_fd, mod_path, strerror(errno));
		goto out;
	}

	if (dwfl_report_offline(dwfl, mod_path, mod_path, dwfl_fd) == NULL) {
		xbt_error("cannot load DWARF from '%s': %s",
			  mod_path, strerror(errno)); /* XXX errno */
		close(dwfl_fd);
		goto out;
	}

	dwfl_report_end(dwfl, NULL, NULL);

	struct xbt_dwfl_module_arg arg = {
		.a_path = mod_path,
		.a_text = text,
		.a_text_offset = addr - text,
	};

	dwfl_getmodules(dwfl, xbt_dwfl_module_cb, &arg, 0 /* offset*/);
	/* ... */
	dwfl_end(dwfl);
out:
	return 0;
}
