from idautils import *
from idc import *
from idaapi import *
import idc, idaapi, idautils, ida_xref
import pickle
import json
import sys

func_list=[]

def serialize(fname,vlist,code):
    global func_list
    return func_list.append({
        "function_name":fname,
        "var_list":vlist,
        "code":code
    })

def ida_get_code(cfunc):
    if cfunc is None:
        return False
    sv = cfunc.get_pseudocode()
    lines = [tag_remove(sline.line) for sline in sv]
    return "".join(lines)


def ida_get_lvars(cfunc):
    if cfunc is None:
        return False
    lvars = cfunc.get_lvars()
    vlist=[{
        "name":lv.name,
        "hasdwarf":lv.has_user_info,
        "isargs":lv.is_arg_var,
        "isreg":lv.is_reg_var()
        } for lv in lvars]
    # print(lv.name,lv.has_user_info)
    return vlist

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
    with open('{}.ida.json'.format(filename), 'w+') as f:
        for fn in idautils.Functions():
            flags = get_func_flags(fn)
              # Ignore THUNK (jump function) or library functons
            if flags & FUNC_LIB or flags & FUNC_THUNK:
                continue
            func = ida_decompile_func(fn)
            if not func:
                continue
            try:
                serialize(
                    get_func_name(fn),
                    ida_get_lvars(func),
                    ida_get_code(func)
                )
            except IOError:
                raise RuntimeError('IO Error')
        json.dump(func_list,f)
    return 

# ./idat64 -c -S"/home/p1umer/Documents/dwarf_research/ida_parse_f5.py" ~/Documents/dwarf_research/database/O0/mujs/build/debug/mujs
if __name__ == "__main__":
    # headless
    filename = get_input_file_path()
    print(filename)
    auto_wait()
    start_traverse(filename)
    qexit(0)
