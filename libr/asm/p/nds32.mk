OBJ_NDS32=asm_nds32.o
OBJ_NDS32+=../arch/nds32/gnu/nds32-dis.o
OBJ_NDS32+=../arch/nds32/gnu/nds32-asm.o
OBJ_NDS32+=../arch/hexagon/gnu/safe-ctype.o
OBJ_NDS32+=../arch/nds32/gnu/hashtab.o


STATIC_OBJ+=${OBJ_NDS32}
TARGET_NDS32=asm_nds32.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_NDS32}

${TARGET_NDS32}: ${OBJ_NDS32}
	${CC} $(call libname,asm_nds32) ${LDFLAGS} ${CFLAGS} -o asm_nds32.${EXT_SO} ${OBJ_NDS32}
endif
