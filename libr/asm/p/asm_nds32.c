/*
 * nds32 disassembly plugin for radare2
 * Copyright (c) 2019, Will Woods <wwoods@redhat.com>
 * Covered under the terms of the LGPLv2+
 */

#include <r_asm.h>
#include <r_lib.h>
#include "disas-asm.h"

/* just pull in the whold dang thing */
//#include "../arch/nds32/gnu/nds32-asm.c"

static unsigned long Offset = 0;
static RStrBuf *buf_global = NULL;
static unsigned char bytes[4];


/* stub functions that gnu disasm uses */
static int nds32_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
    memcpy(myaddr, bytes, length);
    return 0;
}
static int nds32_symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
    return 0;
}
static void nds32_memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
        //--
}

/* make sure we can fprintf etc. */
DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

/* Glue function between binutils code and radare code.
 * Radare's disassemble() function passes us:
 *   a:   asm options (a->pc, a->bits, etc.)
 *   op:  disasm output (op->size, op->buf_asm)
 *   buf: bytes to disassemble
 *   len: size of buf
 * The main entrypoint for disassembly in binutils-land is:
 *   int print_insn_nds32(bfd_vma pc, disassemble_info *info)
 * For a good example, check out asm_ppc_gnu.c.
 */
static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
    struct disassemble_info info;
    /* sanity check - do we even have enough data to disassemble */
    if (len<2) {
        return -1;
    }

    /* prep our global variables */
    buf_global = &op->buf_asm;
    Offset = a->pc;
    memcpy(bytes, buf, 4);

    /* prep disassembler */
    memset(&info, '\0', sizeof(struct disassemble_info));
    info.buffer = bytes;
    info.endian = !a->big_endian;
    info.read_memory_func = &nds32_buffer_read_memory;
    info.symbol_at_address_func = &nds32_symbol_at_address;
    info.memory_error_func = &nds32_memory_error_func;
    info.print_address_func = &generic_print_address_func;
    info.fprintf_func = &generic_fprintf_func;
    info.stream = stdout;

    op->size = print_insn_nds32((bfd_vma)Offset, &info);

    /* TODO: no idea if this is valid/needed but ppc/arm do it, so.. */
    if (op->size == -1) {
        r_strbuf_set(&op->buf_asm, "(data)");
        op->size = 4;
    }
    /* TODO: do we need special handling for "*unknown*"? */

    return op->size;
}

RAsmPlugin r_asm_plugin_nds32 = {
    .name = "nds32",
    .desc = "NDS32",
    .arch = "nds32",
    .bits = 16|32,
    .endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
    .license = "GPL", /* FIXME: is that correct? */
    .disassemble = &disassemble,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_ASM,
        .data = &r_asm_plugin_nds32,
        .version = R2_VERSION
};
#endif
