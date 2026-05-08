    .text
    .globl _start
    .type _start, @function
    .globl cfa_deref_expression
    .type cfa_deref_expression, @function
_start:
cfa_deref_expression:
    .cfi_startproc
    nop
    /* DW_CFA_def_cfa_expression: DW_OP_breg6(RBP) -40; DW_OP_deref */
    .cfi_escape 0x0f, 0x03, 0x76, 0x58, 0x06
    nop
    nop
    ret
    .cfi_endproc
    .size cfa_deref_expression, .-cfa_deref_expression
