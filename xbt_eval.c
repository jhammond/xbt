#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <malloc.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <assert.h>
#include <limits.h> // LONG_MIN
#include "xbt.h"

#define DWARF_SWORD_MIN LONG_MIN /* XXX? */
#define XBT_EVAL_UNSUPP XBT_UNSUPP
#define XBT_EVAL_TODO XBT_TODO
#define XBT_BAD_OP XBT_EVAL_BAD_OP

static bool xbt_eval_abort_on_error = false;

int xbt_dwarf_eval(struct xbt_frame *xf,
		   const char *obj_name,
		   Dwarf_Word *obj, Dwarf_Word *bit_mask, size_t obj_size,
		   const Dwarf_Op *expr, size_t expr_len)
{
	Dwarf_Word E[256];
	size_t K = 0;
	size_t bit_off = 0;
	bool is_value = false;
	int rc;

	memset(obj, 0, obj_size);
	memset(bit_mask, 0, obj_size);

#define OUT(err)							\
	do  {								\
		int _err = (err);					\
		assert(_err <= 0);					\
		if (xbt_eval_abort_on_error && _err != 0)		\
			abort();					\
		rc = _err;						\
		xbt_error("OUT obj %s, K %zu, rc %d", obj_name, K, rc);	\
		goto out;						\
	} while (0)

#define REQ(cond, err)							\
	do {								\
		if (!(cond))						\
			OUT(err);					\
	} while (0)

#define IS_EMPTY() (K == 0)

#define PUSH(w)								\
	do {								\
		Dwarf_Word _w;						\
									\
		REQ(K < XBT_ARRAY_LENGTH(E) - 1, -XBT_EVAL_OVERFLOW);	\
		is_value = false;					\
		_w = (w);						\
		E[K++] = _w;						\
	} while (0)

#define POP()								\
	({								\
		REQ(0 < K, -XBT_EVAL_UNDERFLOW);			\
		is_value = false;					\
		E[--K];							\
	})

#define PEEK(d)								\
	({								\
		size_t _d;						\
									\
		_d = (d);						\
		REQ(_d < K, -XBT_EVAL_UNDERFLOW);			\
		E[K - _d - 1];						\
	})

#define MEM_REF(addr, size)						\
	({								\
		unsigned long _m = 0;					\
		size_t _s;						\
		int _rc;						\
									\
		_s = (size);						\
		REQ(_s <= sizeof(_m), -XBT_EVAL_BAD_OP);		\
									\
		_rc = xf_mem_ref(xf, &_m, (addr), _s);			\
		if (_rc != 0)						\
			OUT(_rc);					\
									\
		_m;							\
	})

#if 0
#define FBREG_REF(off)							\
	({								\
		unsigned long _w;					\
		int _rc;						\
									\
		_rc = xf_frame_ref(xf, &_w, (off));			\
		if (_rc != 0)						\
			OUT(_rc);					\
									\
		_w;							\
	})
#endif

#define FBREG_REF(off)							\
	((off) + xf->xf_frame_end)

#define BREG_REF(reg, off)						\
	({								\
		unsigned long _r;					\
		int _rc;						\
									\
		_rc = xf_reg_ref(xf, &_r, (reg));			\
		if (_rc != 0)						\
			OUT(_rc);					\
									\
		_r + (off);						\
	})

#define PUSH_REG(reg)							\
	do {								\
		unsigned long _r;					\
		int _rc;						\
									\
		_rc = xf_reg_ref(xf, &_r, (reg));			\
		if (_rc != 0)						\
			OUT(_rc);					\
									\
		PUSH(_r);						\
		is_value = true;					\
	} while (0)

	size_t i = 0;
	/* Due to skip, i is also modified in the loop body. */
	for (i = 0; i < expr_len; i++) {
		uint8_t u = expr[i].atom;
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
		case DW_OP_fbreg:
			PUSH(FBREG_REF(n0));
			break;
		case DW_OP_breg0:
		case DW_OP_breg1:
		case DW_OP_breg2:
		case DW_OP_breg3:
		case DW_OP_breg4:
		case DW_OP_breg5:
		case DW_OP_breg6:
		case DW_OP_breg7:
		case DW_OP_breg8:
		case DW_OP_breg9:
		case DW_OP_breg10:
		case DW_OP_breg11:
		case DW_OP_breg12:
		case DW_OP_breg13:
		case DW_OP_breg14:
		case DW_OP_breg15:
		case DW_OP_breg16:
		case DW_OP_breg17:
		case DW_OP_breg18:
		case DW_OP_breg19:
		case DW_OP_breg20:
		case DW_OP_breg21:
		case DW_OP_breg22:
		case DW_OP_breg23:
		case DW_OP_breg24:
		case DW_OP_breg25:
		case DW_OP_breg26:
		case DW_OP_breg27:
		case DW_OP_breg28:
		case DW_OP_breg29:
		case DW_OP_breg30:
		case DW_OP_breg31: {
			Dwarf_Word x;
			x = BREG_REF(u - DW_OP_breg0, n0);
			PUSH(x);
			break;
		}
		case DW_OP_bregx:
			PUSH(BREG_REF(n0, n1));
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
			PUSH(MEM_REF(t0, sizeof(t0)));
			break;
		}
		case DW_OP_deref_size: {
			Dwarf_Word t0;

			t0 = POP();
			PUSH(MEM_REF(t0, n0));
			break;
		}
		case DW_OP_xderef:
			/* Extended dereference: t0 is address, t1 is
			 * address space identifier. */
			OUT(-XBT_EVAL_UNSUPP); /* Not emitted AFAIK. */
		case DW_OP_xderef_size:
			/* Same as xderef exfpet that n0 is the value size. */
			OUT(-XBT_EVAL_UNSUPP); /* Not emitted AFAIK. */
		case DW_OP_push_object_address:
			/* For 'this'? */
			OUT(-XBT_EVAL_UNSUPP); /* Not emitted AFAIK. */
		case DW_OP_form_tls_address:
			OUT(-XBT_EVAL_TODO); /* Not emitted AFAIK. */
		case DW_OP_call_frame_cfa:
			/* CFA computed from CFI. */
			OUT(-XBT_EVAL_TODO); /* Not emitted AFAIK. */

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
			REQ(t0 != 0 && (t0 != -1 || t1 != DWARF_SWORD_MIN),
			    -XBT_EVAL_DIV_ERR);
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
			REQ(t0 != 0 && (t0 != -1 || t1 != DWARF_SWORD_MIN),
			    -XBT_EVAL_DIV_ERR);

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
				OUT(-XBT_EVAL_BAD_OP);

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
			OUT(-XBT_EVAL_UNSUPP); /* Not emitted AFAIK. */

		/* Special operations. */
		case DW_OP_nop:
			break;

		/* Register locations. */	
		case DW_OP_reg0:
		case DW_OP_reg1:
		case DW_OP_reg2:
		case DW_OP_reg3:
		case DW_OP_reg4:
		case DW_OP_reg5:
		case DW_OP_reg6:
		case DW_OP_reg7:
		case DW_OP_reg8:
		case DW_OP_reg9:
		case DW_OP_reg10:
		case DW_OP_reg11:
		case DW_OP_reg12:
		case DW_OP_reg13:
		case DW_OP_reg14:
		case DW_OP_reg15:
		case DW_OP_reg16:
		case DW_OP_reg17:
		case DW_OP_reg18:
		case DW_OP_reg19:
		case DW_OP_reg20:
		case DW_OP_reg21:
		case DW_OP_reg22:
		case DW_OP_reg23:
		case DW_OP_reg24:
		case DW_OP_reg25:
		case DW_OP_reg26:
		case DW_OP_reg27:
		case DW_OP_reg28:
		case DW_OP_reg29:
		case DW_OP_reg30:
		case DW_OP_reg31:
			/* These operations name a register location. */
			PUSH_REG(u - DW_OP_reg0);
			break;
		case DW_OP_regx:
			/* This operation names a register location. */
			PUSH_REG(n0);
			break;

		/* Implicit locations. */
		case DW_OP_implicit_value:
		/* The DW_OP_implicit_value operation specifies an
		   immediate value using two operands: an unsigned
		   LEB128 length, followed by a block representing the
		   value in the memory representation of the target
		   machine. The length operand gives the length in
		   bytes of the block. */
			OUT(-XBT_EVAL_TODO); /* Not emitted AFAIK. */

		case DW_OP_stack_value:
			is_value = true;
			break;

		/* Empty location descriptions.
		   An empty location description consists of a DWARF
		   expression containing no operations. It represents
		   a piece or all of an object that is present in the
		   source but not in the object code (perhaps due to
		   optimization). */

		/* Composite location descriptions. */
		case DW_OP_piece: {
			Dwarf_Word t0, v0 = 0;
			bool have_value = false;

			/* n0 is size in bytes. */
			REQ(bit_off % 8 == 0, -XBT_BAD_OP); /* XXX Safe? */
			REQ(bit_off + 8 * n0 <= 8 * obj_size, -XBT_BAD_OP);

			if (IS_EMPTY()) {
				/* Empty location. */
				xbt_trace("%s[%zu, %zu) location = NONE, value = NONE",
					  obj_name, bit_off, bit_off + 8 * n0);
			} else if (is_value) {
				/* Virtual location. */
				/* TODO Save reg/literal name. */
				t0 = POP();
				memcpy(&v0, &t0, n0);
				have_value = true;

				xbt_trace("%s[%zu, %zu) location = NONE",
					  obj_name, bit_off, bit_off + 8 * n0);
			} else {
				/* Real location. */
				int mem_rc;

				t0 = POP();
				xbt_trace("%s[%zu, %zu) location = %lx",
					  obj_name, bit_off, bit_off + 8 * n0, t0);

				mem_rc = xf_mem_ref(xf, &v0, t0, n0);
				if (mem_rc != 0)
					xbt_trace("%s[%zu, %zu) cannot access %lx: rc = %d",
						  obj_name, bit_off, bit_off + 8 * n0, t0, mem_rc);
				else
					have_value = true;
			}

			if (have_value) {
				xbt_trace("%s[%zu, %zu) value = %lx",
					  obj_name, bit_off, bit_off + 8 * n0, v0);

				memcpy(obj + bit_off / 8, &v0, n0);
				memset(bit_mask + bit_off / 8, 0xff, n0);
			}

			bit_off += 8 * n0;
			break;
		}
		case DW_OP_bit_piece:
			OUT(-XBT_EVAL_TODO); /* Rarely emimtted. */

		/* GNU extensions. */
		case DW_OP_GNU_push_tls_address:
		case DW_OP_GNU_uninit:
		case DW_OP_GNU_encoded_addr:
		case DW_OP_GNU_implicit_pointer:
			OUT(-XBT_EVAL_UNSUPP); /* Not emitted AFAIK. */

		default:
			OUT(-XBT_EVAL_BAD_OP);
		}
	}

	if (bit_off != 0)
		OUT(XBT_OK);

	if (IS_EMPTY())
		OUT(-XBT_BAD_OP); /* Is this ever OK? */

	if (is_value) {
		Dwarf_Word t0;

		t0 = POP();
		memcpy(obj, &t0, obj_size);
		xbt_trace("%s value = %lx", obj_name, t0);
	} else {
		Dwarf_Word t0, v0;
		int mem_rc;

		t0 = POP();
		xbt_trace("%s location = %lx", obj_name, t0);

		mem_rc = xf_mem_ref(xf, &v0, t0, sizeof(v0));
		if (mem_rc != 0) {
			xbt_trace("%s cannot access %lx: rc = %d",
				  obj_name, t0, mem_rc);
		} else {
			/* FIXME */
			memcpy(obj, &v0, obj_size < sizeof(v0) ?
			       obj_size : sizeof(v0));
			xbt_trace("%s value = %lx", obj_name, v0);
		}
	}
	OUT(XBT_OK);
out:
	return rc;
}
