from idautils import *
from idc import *
from idaapi import *
import idc, idaapi, idautils, ida_xref
import json
import sys

func_list=[]

class ModuleInfo:

    ida_num_total = 0
    ida_none_num_total =0
    ida_has_dwarf_total = 0
    ida_reg_num_total = 0
    ida_stack_num_total = 0
    # ida_poly_num_total = 0
    # ida_unknown_num_total = 0
    func_info_list = []

    def add_func_info(self,func_name,
                    ida_num,
                    ida_none_num,
                    ida_has_dwarf,
                    ida_reg_num,
                    ida_stack_num,
                    # dwarf_poly_num,
                    # ida_unknown_num,
                    var_list,
                    code):

        self.ida_num_total+=ida_num
        self.ida_none_num_total+=ida_none_num
        self.ida_has_dwarf_total+=ida_has_dwarf
        self.ida_reg_num_total+=ida_reg_num
        self.ida_stack_num_total+=ida_stack_num

        return self.func_info_list.append({
            "function_name":func_name,
            "ida_num":ida_num,
            "ida_none_num":ida_none_num,
            "ida_has_dwarf":ida_has_dwarf,
            "ida_reg_num":ida_reg_num,
            "ida_stack_num":ida_stack_num,
            # "ida_unknown_num":ida_unknown_num,
            "var_list":var_list,
            "code":code
        })

    def serialize(self):
        return {
            "ModuleInfo":{
                "ida_num_total":self.ida_num_total,
                "ida_none_num_total":self.ida_none_num_total,
                "ida_has_dwarf_total":self.ida_has_dwarf_total,
                "ida_reg_num_total":self.ida_reg_num_total,
                "ida_stack_num_total":self.ida_stack_num_total
            },
            "FunctionInfo":self.func_info_list
        }

class FunctionInfo:
    func_name=None
    ida_num = 0
    ida_none_num=0
    ida_has_dwarf = 0
    ida_reg_num = 0
    ida_stack_num = 0
    # ida_poly_num = 0
    # ida_unknown_num = 0
    var_list = []
    code = None

    def __init__(self):
        self.func_name=None
        self.ida_num = 0
        self.ida_none_num=0
        self.ida_has_dwarf =0
        self.ida_reg_num = 0
        self.ida_stack_num = 0
        # self.ida_unknown_num =0
        self.var_list = []
        self.code=None

    
    def set_func_name(self,name):
        self.func_name = name

    def set_func_code(self,code):
        self.code = code
    
    def add_ida_num(self):
        self.ida_num+=1
        return True

    def __add_ida_reg_num(self):
        self.ida_reg_num+=1
    
    def __add_ida_stack_num(self):
        self.ida_stack_num+=1

    
    def __add_ida_has_dwarf(self):
        self.ida_has_dwarf+=1

    def __add_ida_none_num(self):
        self.ida_none_num+=1
    
    def __none(self):
        pass

    
    def __statistics(self,vname,hasdwarf,ltype):
        self.ida_num+=1
        if vname=="":
            self.__add_ida_none_num()
        if hasdwarf:
            self.__add_ida_has_dwarf()
        # assert (ltype!="None"),"ida variable is neither in STACK nor in REGISTER"
        return {
            "None": (self.__none),
            "Reg": (self.__add_ida_reg_num),
            "Stack": (self.__add_ida_stack_num),
            # "Poly": (self.__add_ida_poly_num)
        }[ltype]()
    
    def add_var_info(self,vname,hasdwarf,ltype):
        self.__statistics(vname,hasdwarf,ltype)
        self.var_list.append({
            "name":vname,
            "hasdwarf":hasdwarf,
            "type":ltype
        })
    
    def serialize(self,minfo):
        return minfo.add_func_info(
            self.func_name,
            self.ida_num,
            self.ida_none_num,
            self.ida_has_dwarf,
            self.ida_reg_num,
            self.ida_stack_num,
            # self.ida_poly_num,
            # self.ida_unknown_num,
            self.var_list,
            self.code
        )


def ida_get_code(cfunc):
    if cfunc is None:
        return False
    sv = cfunc.get_pseudocode()
    lines = [tag_remove(sline.line) for sline in sv]
    return "".join(lines)

def check_location_type(lv):
    ref = 0
    if lv.is_reg_var():
        ref = ref | 1
    if lv.is_stk_var():
        ref = ref | 2
    data=['None','Reg',"Stack","Poly"]
    return data[ref]

def ida_get_lvars(cfunc,finfo):
    if cfunc is None:
        return False
    lvars = cfunc.get_lvars()
    for lv in lvars:
        if lv.is_arg_var:
            continue
        ltype = check_location_type(lv)
        finfo.add_var_info(lv.name,
                        lv.has_user_info,
                        ltype)


def ida_decompile_func(ea):
    if not init_hexrays_plugin():
        return False
    f = get_func(ea)
    if f is None:
        return False
    try:
        cfunc = decompile(f)
        return cfunc
    except:
        # print("[+] ERROR HERE")
        return False

def start_traverse(filename):
    global func_list
    minfo = ModuleInfo()
    with open('{}.ida.json'.format(filename), 'w+') as f:
        for fn in idautils.Functions():
            finfo = FunctionInfo()
            flags = get_func_flags(fn)
              # Ignore THUNK (jump function) or library functons
            if flags & FUNC_LIB or flags & FUNC_THUNK:
                continue
            func = ida_decompile_func(fn)
            if not func:
                continue
            try:
                finfo.set_func_name(get_func_name(fn))
                finfo.set_func_code(ida_get_code(func))
                ida_get_lvars(func,finfo)
                finfo.serialize(minfo)
            except IOError:
                raise RuntimeError('IO Error')
        json.dump(minfo.serialize(),f)
    return 

# ./idat64 -c -S"/home/p1umer/Documents/dwarf_research/ida_parse_f5.py" ~/Documents/dwarf_research/database/O0/mujs/build/debug/mujs
if __name__ == "__main__":
    # headless
    filename = get_input_file_path()
    print(filename)
    auto_wait()
    start_traverse(filename)
    qexit(0)
