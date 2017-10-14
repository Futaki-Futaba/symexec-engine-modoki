#!/bin/env python2
from z3 import *
import random
import copy

def bp():
    raw_input("hit enter to continue...")

class arch(): # Base Architecture Class
    bits = 0
    solver = None           # z3 solver instance
    _id = 0

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

    # State Fields (TODO: Enum)
    FIELD_STATE_CURRPC = 0  # current pc (not looks ahead next instruction; not same as original PC register)
    FIELD_STATE_PREVPC = 1  # previous pc
    FIELD_STATE_ASSERT = 2  # assert
    FIELD_STATE_REG = 3     # registers
    FIELD_STATE_FLAG = 4    # flag registers

    constrained_regs = {}   # dict type
    constrained_flags = {}  # dict type
    insts = []              # loaded instructions
    insts_index = {}        # instructions index by address

    done_load_insts = False

    def __init__(self):
        # Create z3 Solver Instance
        self.solver = Solver()      # clear constraints
        self.constrained_regs = {}  # clear constraints
        self.constrained_flags = {} # clear constraints
        self.done_load_insts = False

    def __del__(self):
        del self.solver

    def Add_Constraint(self, constraints):
        self.solver.add(constraints)

    def Assertions(self):
        return self.solver.assertions()

    # @return: sat, unsat, unknown (they are python constants)

    def Check(self): # checks if it is satisfiable
        return self.solver.check()

    def Get_Model(self):
        return self.solver.model()

    def Get_Models(self):
        raise NotImplementedError("TODO: Get_Models is not implemented")

    def store_reg_symvar(self, name, symvar):
        self.constrained_regs[name] = symvar

    def get_reg_symvar(self, name): # returns symbolic register
        if name in self.constrained_regs.keys(): # already symbolized
            res = self.constrained_regs[name]
            if res == None:
                raise Exception("constrained_regs['%s'] is None!" % name)
            return res
        else: # not already symbolized
            res = BitVec("Reg_%s" % name, self.bits)
            self.store_reg_symvar(name, res)
            return res

    def store_flag_symvar(self, name, symvar):
        self.constrained_flags[name] = symvar

    def get_flag_symvar(self, name):
        if name in self.constrained_flags.keys(): # already symbolized
            return self.constrained_flags[name]
        else: # not already symbolized
            res = Bool("Flag_%s" % name)
            self.store_flag_symvar(name, res)
            return res

    def id(self): # helper function to ensure symbol variable name's uniqueness
        ret = self._id
        self._id += 1
        return ret

    def create_insts_index(self):
        for v in self.insts:
            self.insts_index[v[self.FIELD_INST_ADDR]] = v

    def Load_Insts(self, insts):
        self.insts = insts
        self.create_insts_index()
        self.done_load_insts = True

    def Fetch_Inst(self, addr):
        return self.insts_index[addr]

    # THIS WONTBE WORK. DO NOT USE!!
    # "z3.z3types.Z3Exception: translation of contexts is only supported at base level"
    def Copy_Current_Solver(self): # returns copy of current solver
        # s.translate(main_ctx()) returns copy of current state
        # see https://stackoverflow.com/questions/36364214/how-to-quick-copy-pyz3-solvers
        return self.solver.translate(main_ctx())

    # see http://www.cs.tau.ac.il/~msagiv/courses/asv/z3py/advanced-examples.htm
    def Restore_State(self, state):
        self.solver = Solver()
        self.Add_Constraint(state[self.FIELD_STATE_ASSERT])
        self.constrained_regs = state[self.FIELD_STATE_REG]
        self.constrained_flags = state[self.FIELD_STATE_FLAG]

    def Dump_State(self, pc, prev_pc):
        return (pc, prev_pc, self.Assertions(), copy.copy(self.constrained_regs), copy.copy(self.constrained_flags))

class x64(arch):
    # architecture dependents
    bits = 64
    # REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"] # register number preferred. but register name is kind for beginners
    # FLAGS = ["ZF"]

    def inst_add(self, dst, src): # src type is symvar or int
        _id = self.id()
        res = BitVec("bv_%x_add_res" % _id, self.bits)
        self.solver.add(res == dst + src)
        ZF = Bool("bool_%x_add_ZF" % _id)
        self.solver.add(ZF == (res == 0))
        self.store_flag_symvar("ZF", ZF)
        SF = Bool("bool_%x_add_SF" % _id)
        OF = Bool("bool_%x_add_OF" % _id)
        self.solver.add([SF == (res < 0), OF == False]) # FIXME: OF
        self.store_flag_symvar("SF", SF)
        self.store_flag_symvar("OF", OF)
        return res

    def inst_mov(self, dst, src): # dst is needless
        _id = self.id()
        res = BitVec("bv_%x_mov_res" % _id, self.bits)
        self.solver.add(res == src)
        return res

    def inst_inc(self, dst):
        _id = self.id()
        res = BitVec("bv_%x_inc_res" % _id, self.bits)
        self.solver.add(res == dst + 1)
        return res

    def inst_dec(self, dst):
        _id = self.id()
        res = BitVec("bv_%x_dec_res" % _id, self.bits)
        self.solver.add(res == dst - 1)
        ZF = Bool("bool_%x_dec_ZF" % _id)
        self.solver.add(ZF == (res == 0))
        self.store_flag_symvar("ZF", ZF)
        SF = Bool("bool_%x_dec_SF" % _id)
        OF = Bool("bool_%x_dec_OF" % _id)
        self.solver.add([SF == (res < 0), OF == False]) # FIXME: OF
        self.store_flag_symvar("SF", SF)
        self.store_flag_symvar("OF", OF)
        return res

    def inst_cmp(self, dst, src): # equivalent to 'dst - src'
        _id = self.id()
        ZF = Bool("bool_%x_cmp_ZF" % _id)
        self.Add_Constraint(ZF == (dst == src))
        self.store_flag_symvar("ZF", ZF)
        SF = Bool("bool_%x_cmp_SF" % _id)
        OF = Bool("bool_%x_cmp_OF" % _id)
        self.solver.add([SF == (dst < src), OF == False]) # FIXME: OF
        self.store_flag_symvar("SF", SF)
        self.store_flag_symvar("OF", OF)

    def inst_jz_imm(self, dst, pc, next_pc):
        ret = []
        ZF = self.get_flag_symvar("ZF")
        self.solver.push()
        self.Add_Constraint(ZF == False)
        if self.Check() == sat:
            S_false = self.Dump_State(next_pc, pc)
            ret += [S_false]
        self.solver.pop()
        self.solver.add(ZF == True)
        if self.Check() == sat:
            S_true = self.Dump_State(next_pc + dst, pc)
            ret += [S_true]
        return ret

    def inst_jnz_imm(self, dst, pc, next_pc):
        ret = []
        ZF = self.get_flag_symvar("ZF")
        self.solver.push()
        self.Add_Constraint(ZF == True)
        if self.Check() == sat:
            S_false = self.Dump_State(next_pc, pc)
            ret += [S_false]
        self.solver.pop()
        self.solver.add(ZF == False)
        if self.Check() == sat:
            S_true = self.Dump_State(next_pc + dst, pc)
            ret += [S_true]
        return ret

    def inst_jg_imm(self, dst, pc):
        ret = []
        ZF = self.get_flag_symvar("ZF")
        SF = self.get_flag_symvar("SF")
        OF = self.get_flag_symvar("OF")
        self.solver.push()
        self.Add_Constraint(Or(ZF != False, SF != OF)) # s.add(not (x == y)) is not 'x \neq y', s.add(x or y) is not 'x \vee y'
        if self.Check() == sat: # check if not jumps
            S_false = self.Dump_State(next_pc, pc)
            ret += [S_false]
        self.solver.pop()
        self.Add_Constraint(And(ZF == False, SF == OF))
        if self.Check() == sat: # check if jumps
            S_true = self.Dump_State(next_pc + dst, pc)
            ret += [S_true]
        return ret

    def inst_jl_imm(self, dst, pc, next_pc):
        ret = []
        SF = self.get_flag_symvar("SF")
        OF = self.get_flag_symvar("OF")
        self.solver.push()
        self.Add_Constraint(SF == OF)
        if self.Check() == sat: # check if not jumps
            S_false = self.Dump_State(next_pc, pc)
            ret += [S_false]
        self.solver.pop()
        self.Add_Constraint(SF != OF) # s.add(not (x == y)) is not 'x \neq y'
        if self.Check() == sat: # check if jumps
            S_true = self.Dump_State(next_pc + dst, pc)
            ret += [S_true]
        return ret

    # function pointer list
    call = {
        "add": inst_add,
        "mov": inst_mov,
        "inc": inst_inc,
        "dec": inst_dec,
        "cmp": inst_cmp,
        "jz_imm": inst_jz_imm,
        "jnz_imm": inst_jnz_imm,
        "je_imm": inst_jz_imm,
        "jne_imm": inst_jnz_imm,
        "jg_imm": inst_jg_imm,
        "jl_imm": inst_jl_imm,
    }

    def Exec(self, inst, state):
        # NOTE: I'm Considering only registers and immediate values now
        pc = state[self.FIELD_STATE_CURRPC]
        self.Restore_State(state)
        print inst
        inst_name = inst[self.FIELD_INST_NAME]
        inst_size = inst[self.FIELD_INST_SIZE]
        inst_op_type = inst[self.FIELD_INST_OP_TYPE]
        if inst_op_type & (self.OP_TYPE_RDST | self.OP_TYPE_IVAL):
            inst_op_dst = inst[self.FIELD_INST_OP_DST]
        if (inst_op_type & self.OP_TYPE_RDST) and (inst_op_type & (self.OP_TYPE_RSRC | self.OP_TYPE_IVAL)):
            inst_op_src = inst[self.FIELD_INST_OP_SRC]
        if inst_name in ["add", "mov"]: # handle insts such as "dst = f(dst, src)"
            if inst_op_type & self.OP_TYPE_RDST:
                dst = self.get_reg_symvar(inst[self.FIELD_INST_OP_DST])
                if inst_op_src == None:
                    raise Exception("missing RSC/IVAL")
                src = None
                if inst_op_type & self.OP_TYPE_RSRC:
                    src = self.get_reg_symvar(inst_op_src)
                elif inst_op_type & self.OP_TYPE_IVAL:
                    src = inst_op_src
                try:
                    ret = self.call[inst_name](self, dst, src)
                    self.store_reg_symvar(inst_op_dst, ret) # update register symvar
                except KeyError:
                    print "[!] unsupported inst_name: %s" % inst_name
                    exit(1)
                return [self.Dump_State(pc + inst_size, pc)]
            raise Exception("RDST is not given: %s" % str(inst))
        if inst_name in ["cmp"]: # handle insts such as f(dst, src)
            if inst_op_type & self.OP_TYPE_RDST:
                dst = self.get_reg_symvar(inst_op_dst)
                src = None
                if inst_op_type & self.OP_TYPE_RSRC:
                    src = self.get_reg_symvar(inst_op_src)
                elif inst_op_type & self.OP_TYPE_IVAL:
                    src = inst_op_src
                else:
                    raise Exception("missing RSC/IVAL")
                try:
                    self.call[inst_name](self, dst, src) # NO RETURN VALUE
                except KeyError:
                    print "[!] unsupported inst_name: %s" % inst_name
                    exit(1)
                return [self.Dump_State(pc + inst_size, pc)]
            raise Exception("RDST is not given: %s" % str(inst))
        elif inst_name in ["dec", "inc"]:
            if inst_op_type & self.OP_TYPE_RDST:
                dst = self.get_reg_symvar(inst_op_dst)
                ret = self.call[inst_name](self, dst)
                self.store_reg_symvar(inst_op_dst, ret) # update register symvar
                return [self.Dump_State(pc + inst_size, pc)]
            raise Exception("RDST is not given: %s" % str(inst))
        elif inst_name in ["je", "jne", "jz", "jnz", "jg", "jl"]:
            if inst_op_type & self.OP_TYPE_IVAL:
                dst = inst_op_dst
                next_pc = pc + inst_size
                ret = self.call[inst_name + "_imm"](self, dst, pc, next_pc)
                # print ret # for debugging
                # bp() # for debugging
                return ret
            raise Exception("IVAL (immediate value) is not given: %s" % str(inst))
        elif inst_name in ["nop"]:
            return [(pc + inst_size, pc, 
                state[self.FIELD_STATE_ASSERT], self.constrained_regs, self.constrained_flags)] # without copy
        else:
            raise NotImplementedError("unsupported instruction: %s" % str(inst))

def KLEE_like_heuristic(StateList):
    print "[!] implement me correctly!!"
    return random.randint(0, len(StateList) - 1)

def test_heuristic(StateList):
    return 0

def Deque_according_R(ActiveStates, R):
    target_index = R(ActiveStates)
    ret = ActiveStates[target_index]
    ActiveStates.remove(ret)
    return ret

def test(): # write test code here...
    arr = [0, 1, 2]
    R = lambda x: 1
    Deque_according_R(arr, R)
    assert(len(arr) == 2 and arr[1] == 2)

    MAGIC_NUMBER = 114514
    engine = x64()

    print "[-] checking symbolic registers"
    engine.get_reg_symvar("rax")
    assert("rax" in engine.constrained_regs.keys())
    engine.store_reg_symvar("rbx", MAGIC_NUMBER)
    assert(engine.get_reg_symvar("rbx") == MAGIC_NUMBER)

    print "[-] checking symbolic flags registers"
    engine.get_flag_symvar("ZF")
    assert("ZF" in engine.constrained_flags.keys())
    engine.store_flag_symvar("SF", MAGIC_NUMBER)
    assert(engine.get_flag_symvar("SF") == MAGIC_NUMBER)

    del engine # FIXME: NOT WORKS

# @param    engine : instance of engine instance (X64(), ...)
# @param    find : list of address to change current state to success state
# @param    avoid : list of address to kill current state
# @return   success_states : list of z3.Solver.assumptions()
def start_Execution_Loop(engine, find, avoid, find_hook=None):
    if not engine.done_load_insts:
        raise Exception("load instructions first")

    print "[*] find = %s" % find
    print "    avoid = %s\n" % avoid

    S_init = engine.Dump_State(0, 0)

    print "[*] we are in main execution loop..."
    """========== Main Execution Loop ========="""
    ActiveStates = [S_init]
    SuccessStates = []
    finished = False
    iter_count = 0
    while (not ActiveStates == []) and (not finished):
        iter_count += 1
        S = Deque_according_R(ActiveStates, test_heuristic)
        p = S[arch.FIELD_STATE_CURRPC]
        I = engine.Fetch_Inst(p)
        # print "pc = %2x, inst = %s" % (p, I)
        # print "assertions: %s" % S[arch.FIELD_STATE_ASSERT]
        # bp()
        S_new = engine.Exec(I, S)
        for S_prime in S_new:
            next_pc = S_prime[arch.FIELD_STATE_CURRPC]
            if next_pc in find:
                if find_hook:
                    sat_check, S_second = find_hook(engine, S_prime) # S_second may None
                    if sat_check:
                        finished = True
                        SuccessStates += [S_second]
                        print "[*] reached to find (|SuccessStates| = %d)" % len(SuccessStates)
                    else:
                        print "[!] reached to find. but unsat. omitting this state"
                        pass
                else:
                    SuccessStates += [S_prime]
                    print "[*] reached to find (|SuccessStates| = %d)" % len(SuccessStates)
            elif next_pc in avoid:
                print "[*] reached to avoid. omitting this state"
            else:
                ActiveStates += [S_prime]
        if len(SuccessStates) > 4: # anti infinite loop
            print "[!] there's enough successors. breaking loop"
            break
        if iter_count > 100:
            print "[!] exceeded iteration count limit. breaking loop"
            break
    else:
        print "[*] ActiveStates is empty!"
    """====== end of Main Execution Loop ======"""
    ret = []
    for S in SuccessStates:
        ret += [S[arch.FIELD_STATE_ASSERT]]
    return ret

def load_Assersions(engine, assersions):
    engine.solver = Solver()
    engine.solver.add(assersions)

if __name__ == '__main__':
    test()
    print "[+] Congratz! self tests passed"
else:
    print "[*] welcome to Symbolic Execution Engine Modoki"
    print ""