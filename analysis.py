# function name
# variable recognize 
# variable unrecognize
# variable added

# dwarf = ida_hit_in_dwarf(recognized) + ida_miss_in_dwarf(unrecognized) + dwarf_has_no_name
#                        
# ida   = ida_add + ida_hit_in_dwarf(recognized)

# ida_add = ida_add + PARTOF ida_miss_in_dwarf(unrecognized)


# ida_miss = unrecognize_in_dwarf

# known :

    # dwarf number:
    # ida number:

# calc:
    # 1. ida var in dwarf? = recognize
    # 2. ida var -recognize = not in dwarf
    # 3. dwarf - recognize = unrecognize
    # 4. ida - 

import json
import sys

func_list=[]

func_name=None
ida_num =0
ida_identified_num = 0
ida_unknown = 0 # part of ida_unidentified_num + ida_add
ida_unidentified_num = 0 # dwarf_num - dwarf_none - ida_identified_num
dwarf_num=0
dwarf_none = 0

# ugly code
def clear_cache():
    global func_name,ida_num,ida_identified_num,ida_unknown,ida_unidentified_num,dwarf_num,dwarf_none
    func_name=None
    ida_num =0
    ida_identified_num = 0
    ida_unknown = 0 
    ida_unidentified_num = 0 
    dwarf_num=0
    dwarf_none = 0

def serialize():
    global func_name,ida_num,ida_identified_num,ida_unknown,ida_unidentified_num,dwarf_num,dwarf_none
    global func_list
    return func_list.append({
        "func_name":func_name,
        "ida_num":ida_num,
        "ida_identified_num":ida_identified_num,
        "ida_unknown":ida_unknown,
        "ida_unidentified_num":ida_unidentified_num,
        "dwarf_num":dwarf_num,
        "dwarf_none":dwarf_none
    })

def find_dwarf_func(dfunc_list,fname):
    global func_name
    func_name = fname
    # search in dfunc_list
    candidates = [df for df in dfunc_list if df['function_name']==fname]
    # check number of candidates, must be 1
    assert len(candidates)<=1,"Error dwarf function number"
    return candidates[0]
    
def analysis_dfunc(dfunc):
    global dwarf_num,dwarf_none
    dwarf_num = len(dfunc['var_list'])
    dwarf_none = len([dv for dv in dfunc['var_list'] if dv['name']==""])
    return

def deep_analysis_ifunc():
    global ida_num,ida_identified_num,ida_unknown,ida_unidentified_num,dwarf_num,dwarf_none
    # maybe negative since ida_identified_num stands for number all IDENTIFIED vars
    # but the vars may be duplicate
    ida_unidentified_num = dwarf_num - dwarf_none - ida_identified_num
    ida_unknown = ida_num - ida_identified_num

def intersect_varlist(ilist,dlist):
    global ida_identified_num,func_name
    var_map={}
    for dl in dlist:
        var_map[dl['name']]=1
    print(func_name)
    for il in ilist:
        print(il)
        if il['name']=='' or il['isargs']==True or il['hasdwarf']==False:
            continue
        # assert var_map[il['name']],"IDA must has symbol here"
        ida_identified_num+=1
    return 

def analysis_ifunc(ifunc,dfunc):
    global ida_num,ida_identified_num
    ida_num = len(ifunc['var_list'])
    intersect_varlist(
        ifunc['var_list'],
        dfunc['var_list'])
    deep_analysis_ifunc()
    return 

def analysis(ijson_file,djson_file):
    print(ijson_file,djson_file)
    with open(ijson_file, 'rb') as ijson, open(djson_file, 'rb') as djson:
        ifunc_list,dfunc_list= json.load(ijson),json.load(djson)
        for ifunc in ifunc_list:
            clear_cache()
            try:
                dfunc = find_dwarf_func(dfunc_list,ifunc['function_name'])
            except:
                print("[*] Cannot find function {} in dwarf".format(ifunc['function_name']))
                continue
            analysis_dfunc(dfunc)
            analysis_ifunc(ifunc,dfunc)
            serialize()
        

if __name__ == "__main__":
    # check file
    binary = sys.argv[1]
    ida_json_file,dwarf_json_file = binary+'.ida.json',binary+'.dwarf.json'
    with open('{}.ans.json'.format(binary), 'w+') as f:
        analysis(ida_json_file,dwarf_json_file)
        json.dump(func_list,f)




