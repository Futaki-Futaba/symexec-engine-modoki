#!/bin/env python2
from symexec import *
from z3 import *

def find_hook(engine, state):
    print "[*] adding constaints to current state"
    engine.Restore_State(state)
    rax = engine.get_reg_symvar("rax")
    engine.Add_Constraint(rax == 16)
    check_sat = engine.Check() == sat
    if check_sat:
        pc = state[engine.FIELD_STATE_CURRPC]
        prev_pc = state[engine.FIELD_STATE_PREVPC]
        return (True, engine.Dump_State(pc, prev_pc))
    else: # Optimization
        return (False, None)

# rax == rdx * (2 ** rsi)
"""
00000000  4883FE01          cmp rsi,byte +0x1
00000004  7C08              jl 0xe
00000006  4801D2            add rdx,rdx
00000009  48FFCE            dec rsi
0000000C  75F8              jnz 0x6
0000000E  4839C2            cmp rdx,rax
00000011  7401              jz 0x14
00000013  C3                ret
00000014  90                nop
"""
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

print "[*] we are going to execute following instructions:"
print '\n'.join([str(x) for x in insts])
print ""

print "[*] initializing engine..."
engine = x64()
engine.Load_Insts(insts)
assert(not engine.solver == None)

print "[*] adding some initial state"
rsi = BitVec("init_rsi", engine.bits)
engine.store_reg_symvar("rsi", rsi)
rdx = BitVec("init_rdx", engine.bits)
engine.store_reg_symvar("rdx", rdx)
rax = BitVec("init_rax", engine.bits)
engine.store_reg_symvar("rax", rax)
# engine.Add_Constraint([rsi == 3, rdx == 2])
engine.Add_Constraint(Or(rsi == 2, rsi == 3))
# engine.Add_Constraint([rsi > 0, rdx == 2])
print "assersions: %s" % str(engine.Assertions())
print ""

find = [0x14]
avoid = [0x13]

# SuccessStates = start_Execution_Loop(engine, find=find, avoid=avoid, find_hook=find_hook)
SuccessStates = start_Execution_Loop(engine, find=find, avoid=avoid)
print ""
for S in SuccessStates:
    print "-"*40
    print "[*] loading assersions which leads success state. let's check it is sat"
    load_Assersions(engine, S)
    print "[*] adding constaints to current state"
    rax = engine.get_reg_symvar("rax")
    new_constraints = [rax == 16]
    print new_constraints
    engine.Add_Constraint(new_constraints)
    # print "[*] assertions:"
    # print engine.Assertions()
    print "[*] sat check:"
    check_res = engine.Check()
    print check_res
    if not check_res == unsat:
        print "[*] solusion for (rsi, rdx, rax):"
        m = engine.Get_Model()
        # print m
        print "rsi = " + str(m[rsi])
        print "rdx = " + str(m[rdx])
        print "rax = " + str(m[rax])