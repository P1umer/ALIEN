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

func_info_list=[]

class FunctionInfo:

    func_name=None
    ida_num =0
    ida_identified_num = 0
    ida_unknown = 0 # part of ida_unidentified_num + ida_add
    ida_unidentified_num = 0 # dwarf_num - dwarf_none - ida_identified_num
    dwarf_num = 0
    dwarf_none_num = 0
    
    def set_func_name(self,name):
        self.func_name = name
    
    def set_ida_num(self,num):
        self.ida_num = num
    
    def get_ida_num(self):
        return self.ida_num
    
    def set_ida_identified_num(self,num):
        self.ida_identified_num = num
    
    def get_ida_identified_num(self):
        return self.ida_identified_num
    
    def add_ida_identified_num(self,num):
        self.ida_identified_num+=num

    def set_ida_unknown(self,num):
        self.ida_unknown = num
    
    def get_ida_unknown(self):
        return self.ida_unknown
    
    def set_ida_unidentified_num(self,num):
        self.ida_unidentified_num = num
    
    def get_ida_unidentified_num(self):
        return self.ida_unidentified_num
    
    def set_dwarf_num(self,num):
        self.dwarf_num = num
    
    def get_dwarf_num(self):
        return self.dwarf_num
    
    def set_dwarf_none_num(self,num):
        self.dwarf_none_num = num
    
    def get_dwarf_none_num(self):
        return self.dwarf_none_num
    
    def serialize(self):
        global func_info_list
        return func_info_list.append({
            "func_name":self.func_name,
            "ida_num":self.ida_num,
            "ida_identified_num":self.ida_identified_num,
            "ida_unknown":self.ida_unknown,
            "ida_unidentified_num":self.ida_unidentified_num,
            "dwarf_num":self.dwarf_num,
            "dwarf_none_num":self.dwarf_none_num
        })


def find_dwarf_func(function_info,dfunc_list,fname):
    function_info.func_name = fname
    # search in dfunc_list
    candidates = [df for df in dfunc_list if df['function_name']==fname]
    # check number of candidates, must be 1
    assert len(candidates)<=1,"Error dwarf function number"
    return candidates[0]
    
def analysis_dfunc(finfo, dfunc):
    finfo.set_dwarf_num(len(dfunc['var_list']))
    finfo.set_dwarf_none_num(len([dv for dv in dfunc['var_list'] if dv['name']==""]))
    return

def deep_analysis_ifunc(finfo):
    # maybe negative since ida_identified_num stands for number all IDENTIFIED vars
    # but the vars may be duplicate
    finfo.set_ida_unidentified_num(finfo.get_dwarf_num() - finfo.get_dwarf_none() - finfo.get_ida_identified_num())
    finfo.set_ida_unknown(finfo.get_ida_num() - finfo.get_ida_identified_num())

def intersect_varlist(finfo,ilist,dlist):
    var_map={}
    for dl in dlist:
        var_map[dl['name']]=1
    for il in ilist:
        print(il)
        if il['name']=='' or il['isargs']==True or il['hasdwarf']==False:
            continue
        # assert var_map[il['name']],"IDA must has symbol here"
        finfo.add_ida_identified_num(1)
    return 

def analysis_ifunc(finfo,ifunc,dfunc):
    finfo.set_ida_num(len(ifunc['var_list']))
    intersect_varlist(finfo,
        ifunc['var_list'],
        dfunc['var_list'])
    deep_analysis_ifunc(finfo)
    return 

def analysis(ijson_file,djson_file):
    print(ijson_file,djson_file)
    with open(ijson_file, 'rb') as ijson, open(djson_file, 'rb') as djson:
        ifunc_list,dfunc_list= json.load(ijson),json.load(djson)
        for ifunc in ifunc_list:
            finfo = FunctionInfo()
            try:
                dfunc = find_dwarf_func(finfo,dfunc_list,ifunc['function_name'])
            except:
                print("[*] Cannot find function {} in dwarf".format(ifunc['function_name']))
                continue
            analysis_dfunc(finfo,dfunc)
            analysis_ifunc(finfo,ifunc,dfunc)
            finfo.serialize()
        

if __name__ == "__main__":
    # check file
    binary = sys.argv[1]
    ida_json_file,dwarf_json_file = binary+'.ida.json',binary+'.dwarf.json'
    with open('{}.ans.json'.format(binary), 'w+') as f:
        analysis(ida_json_file,dwarf_json_file)
        json.dump(func_info_list,f)




