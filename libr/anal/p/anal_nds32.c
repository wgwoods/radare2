/* radare - LGPL - Copyright 2019 Will Woods <w@wizard.zone> */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_lib.h>

// #include "../../asm/arch/nds32/gnu/nds32-asm.h"
#include "ansidecl.h"
#include "../../asm/arch/include/opcode/nds32.h"

// extern (struct nds32_opcode *) nds32_opcode_find(uint32_t insn, uint32_t parse_mode);

static int nds32_op16(RAnal *anal, RAnalOp *op, ut64 addr, ut16 insn);
static int nds32_op32(RAnal *anal, RAnalOp *op, ut64 addr, ut32 insn);

static int nds32_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ut32 insn;

        op->addr = addr;
        op->type = R_ANAL_OP_TYPE_UNK;

        /* Grab the instruction and figure out if it's 32 or 16 bit */
	insn = r_read_be32 (buf);
        if (insn & 0x80000000) {
            op->size = nds32_op16(anal, op, addr, insn>>16);
        } else {
            op->size = nds32_op32(anal, op, addr, insn);
        }

        return op->size;
}

#define JREG_RET N32_BIT(5)

static int nds32_op32(RAnal *anal, RAnalOp *op, ut64 addr, ut32 insn) {
    /* So what do we have? Let's look at the operator group.. */
    switch (N32_OP6(insn))
    {
        /* Register-based jumps / returns */
        case N32_OP6_JREG:
            if (insn & JREG_RET) {
                op->type = R_ANAL_OP_TYPE_RET;
                op->eob = 1;
            } else {
                if (insn & N32_JREG_JRAL) {
                    op->type = R_ANAL_OP_TYPE_CALL;
                } else {
                    op->type = R_ANAL_OP_TYPE_RJMP;
                    op->eob = 1;
                }
            }
            break;

        /* Jump Immediate */
        case N32_OP6_JI:
            op->jump = N32_IMM24S(insn) << 1;
            op->fail = addr + 4;
            if (insn & N32_BIT(24)) {
                op->type = R_ANAL_OP_TYPE_CALL;
            } else {
                op->type = R_ANAL_OP_TYPE_JMP;
                op->eob = 1;
            }
            break;

        /* Conditional branching */
        case N32_OP6_BR1:
            op->jump = addr + (N32_IMM14S(insn) << 1);
            op->fail = addr + 4;
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->cond = (insn & N32_BIT(14)) ? R_ANAL_COND_NE : R_ANAL_COND_EQ;
            op->eob = 1;
            break;

        case N32_OP6_BR2:
            op->jump = addr + (N32_IMM16S(insn) << 1);
            op->fail = addr + 4;
            if (N32_BR2_SUB(insn) & 8) {
                op->type = R_ANAL_OP_TYPE_CCALL;
            } else {
                op->type = R_ANAL_OP_TYPE_CJMP;
                op->eob = 1;
            }
            /* TODO: mapping for N32_BR2_* to R_ANAL_COND_* for op->cond */
            break;

        case N32_OP6_BR3:
            op->jump = addr + (N32_IMMS(insn, 8) << 1);
            op->fail = addr + op->size;
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->cond = (insn & N32_BIT(19)) ? R_ANAL_COND_NE : R_ANAL_COND_EQ;
            op->eob = 1;
            break;
    }
    return 4;
}

static int nds32_op16(RAnal *anal, RAnalOp *op, ut64 addr, ut16 insn) {
    switch (__GF(insn, 5, 10))
    {
        case N16_T5_JRAL5:
            op->type = R_ANAL_OP_TYPE_RCALL;
            return 2;
        case N16_T5_JR5:
            op->type = R_ANAL_OP_TYPE_RJMP;
            op->eob = 1;
            return 2;
        case N16_T5_RET5:
            op->type = R_ANAL_OP_TYPE_RET;
            op->eob = 1;
            return 2;
        case N16_T5_BREAK16:
            return 2;
    }
    switch (__GF(insn, 8, 7))
    {
        case N16_T8_J8:
            op->type = R_ANAL_OP_TYPE_JMP;
            op->jump = addr + (N16_IMM8S(insn) << 1);
            op->eob = 1;
            return 2;
        case N16_T8_BEQZS8:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (N16_IMM8S(insn) << 1);
            op->fail = addr + 2;
            op->eob = 1;
            return 2;
        case N16_T8_BNEZS8:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (N16_IMM8S(insn) << 1);
            op->fail = addr + 2;
            op->eob = 1;
            return 2;
    }
    switch (__GF(insn, 11, 4))
    {
        case N16_T38_BEQZ38:
        case N16_T38_BNEZ38:
        case N16_T38_BEQS38:
        case N16_T38_BNES38:
            op->type = R_ANAL_OP_TYPE_CJMP;
            op->jump = addr + (N16_IMM8S(insn) << 1);
            op->fail = addr + 2;
            op->eob = 1;
            return 2;
    }
    return 2;
}

static int set_reg_profile(RAnal *anal) {
	// TODO: Reduced-register config
	const char *p =
		"=PC	pc\n"
		"=SP	r31\n"
		"=BP	r30\n"

		"gpr	r0	.32	0   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	r30	.32	120 0\n"
		"gpr	r31	.32	124 0\n";

	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_nds32 = {
	.name = "nds32",
	.desc = "Andes Technology (nds32)",
	.license = "LGPL3",
	.arch = "nds32",
	.bits = 32|16,
	.op = nds32_op,
	.esil = true,
	.set_reg_profile = set_reg_profile,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_nds32,
	.version = R2_VERSION
};
#endif
