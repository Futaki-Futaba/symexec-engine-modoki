Symbolic Execution Engine Modoki
====

What is this?
----
* this is Symbolic Engine built on z3py
* and well(?) designed for education scene
* but there're very tight limitations 
    * for more information, see Limitations

How to run?
----
try running test script:

```bash
./test.py
```

Requirements
----
* python2 
* z3py
* (nasm/ndisasm)

Limitations
----
### target machine 
Currently, engine targets following machine spec:

* based on Intel architecture
* supports x86_64 ISA partially
* NO data memory (Only Code on memory)
* NO stack

### instructions
Following few Intel x86_64 instructions are supported:

* add
* mov
* inc
* dec
* cmp
* jz (je)
* jnz (jne)
* jg 
* jl

There may be miss understanding semantics.

Instructions must be decoded like:

```python
insts = [
    (0x0,   4, arch.OP_TYPE_RDST | arch.OP_TYPE_IVAL, "cmp", "rsi", 1),
    (0x4,   2, arch.OP_TYPE_IVAL, "jl", 8), # 0x6 + 8 = 0xe
    (0x6,   3, arch.OP_TYPE_RDST | arch.OP_TYPE_RSRC, "add", "rdx", "rdx"),
    (0x9,   3, arch.OP_TYPE_RDST, "dec", "rsi"),
    (0xc,   2, arch.OP_TYPE_IVAL, "jnz", -8), # 0xe - 8 = 0x6
    (0xe,   3, arch.OP_TYPE_RDST | arch.OP_TYPE_RSRC, "cmp", "rdx", "rax"),
    (0x11,  2, arch.OP_TYPE_IVAL, "je", 1), # 0x13 + 1 = 0x14
    (0x13,  1, arch.OP_TYPE_NOOP, "ret"),
    (0x14,  1, arch.OP_TYPE_NOOP, "nop"),
]
```

each fileds means:

```python
    # decoded instruction format
    FIELD_INST_ADDR = 0      # instruction address
    FIELD_INST_SIZE = 1      # instruction byte size
    FIELD_INST_OP_TYPE = 2   # instruction operand types
    FIELD_INST_NAME = 3      # instruction name 
    FIELD_INST_OP_DST = 4    # instrunction destination X
    FIELD_INST_OP_SRC = 5    # instruction source X

    # operand type
    OP_TYPE_NOOP = 1 << 0       # no operands
    OP_TYPE_RDST = 1 << 1       # destination register. if memory, None
    OP_TYPE_RSRC = 1 << 2       # source register. if memory, None
    OP_TYPE_IVAL = 1 << 3       # immediate value
    OP_TYPE_MDST = 1 << 4       # future work (memory address or register name comes here for simplicity)
    OP_TYPE_MSRC = 1 << 5       # future work    
```

### registers 
supports:

* general registers: all
* flag registers: ZF, SF

not supports:

* flag registers: CF, OF, and so on

### refactoring 
This is alpha version. Hard effort to refactoring (including spell miss) is needed.