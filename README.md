Symbolic Execution Engine Modoki
====

What is this?
----
* this is Symblic Engine built on z3py
* and well(?) designed for education scene
* but there're very tight limitaons 
    * for more information, see Limitations

How to run?
----
try runing test script:

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
* supports x86_64 ISA parcially
* NO data memory (Only Code on memory)
* NO stack

### instructions
Following few intel x86_64 instructions are supported:

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
    (0x0,   4, "cmp", "rsi", None, 1),
    (0x4,   2, "jl", None, None, 8), # 0x6 + 8 = 0xe
    (0x6,   3, "add", "rdx", "rdx"),
    (0x9,   3, "dec", "rsi", None),
    (0xc,   2, "jnz", None, None, -8), # 0xe - 8 = 0x6
    (0xe,   3, "cmp", "rdx", "rax"),
    (0x11,  2, "je", None, None, 1), # 0x13 + 1 = 0x14
    (0x13,  1, "ret"),
    (0x14,  1, "nop"),
]
```

each fileds means:

```python
    # Instuction Fields (TDOO: Enum)
    FIELD_INST_ADDR = 0     # instruction address
    FIELD_INST_SIZE = 1     # instruction byte size
    FIELD_INST_NAME = 2     # instruction name
    FIELD_INST_RDST = 3     # destination register. if memory, None
    FIELD_INST_RSRC = 4     # source register. if memory, None
    FIELD_INST_IVAL = 5     # immediate value
    FIELD_INST_MDST = 6     # future work (memory address or register name comes here for simplicity)
    FIELD_INST_MSRC = 7     # future work
```

### registers 
suppors:

* general registers: all
* flag registers: ZF, SF

not supports:

* flag registers: CF, OF, and so on

### refactering 
This is alpha version. Hard effort to refactering (including spell miss) is nedded.