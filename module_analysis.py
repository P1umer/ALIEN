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

class ModuleInfo:

    # ida info
    ida_num_total = 0
    ida_none_num_total =0
    ida_has_dwarf_total = 0
    ida_reg_num_total = 0
    ida_stack_num_total = 0

    # dwarf info
    dwarf_num_total = 0
    dwarf_none_num_total = 0
    dwarf_reg_num_total = 0
    dwarf_stack_num_total = 0
    dwarf_poly_num_total = 0
    dwarf_unknown_num_total = 0

    # ans info
    ans_ida_identified_num_total =0 

    func_info_list = []


    def add_func_info(self,func_name,ida_num,ida_none_num,
                    ida_has_dwarf,ida_reg_num,ida_stack_num,
                    dwarf_num,dwarf_none_num,dwarf_reg_num,
                    dwarf_stack_num,dwarf_poly_num,dwarf_unknown_num,
                    ans_ida_identified_num):

        self.ans_ida_identified_num_total+=ans_ida_identified_num

        return self.func_info_list.append({
            "func_name":func_name,
            "ida_num":ida_num,
            "ida_none_num":ida_none_num,
            "ida_has_dwarf":ida_has_dwarf,
            "ida_reg_num":ida_reg_num,
            "ida_stack_num":ida_stack_num,

            "dwarf_num":dwarf_num,
            "dwarf_none_num":dwarf_none_num,
            "dwarf_reg_num":dwarf_reg_num,
            "dwarf_stack_num":dwarf_stack_num,
            "dwarf_poly_num":dwarf_poly_num,
            "dwarf_unknown_num":dwarf_unknown_num,

            "ans_ida_identified_num":ans_ida_identified_num,

        })
    def __init__(self,ijson,djson):
        i,d=ijson['ModuleInfo'],djson['ModuleInfo']

        self.ida_num_total=i['ida_num_total']
        self.ida_none_num_total=i['ida_none_num_total']
        self.ida_has_dwarf_total=i['ida_has_dwarf_total']
        self.ida_reg_num_total=i['ida_reg_num_total']
        self.ida_stack_num_total=i['ida_stack_num_total']
        self.dwarf_num_total=d['dwarf_num_total']
        self.dwarf_none_num_total=d['dwarf_none_num_total']
        self.dwarf_reg_num_total=d['dwarf_reg_num_total']
        self.dwarf_stack_num_total=d['dwarf_stack_num_total']
        self.dwarf_poly_num_total=d['dwarf_poly_num_total']
        self.dwarf_unknown_num_total=d['dwarf_unknown_num_total']
        pass

    def serialize(self):
        return {
            "ModuleInfo":{
                "ida_num_total":self.ida_num_total,
                "ida_none_num_total":self.ida_none_num_total,
                "ida_has_dwarf_total":self.ida_has_dwarf_total,
                "ida_reg_num_total":self.ida_reg_num_total,
                "ida_stack_num_total":self.ida_stack_num_total,
                "dwarf_num_total":self.dwarf_num_total,
                "dwarf_none_num_total":self.dwarf_none_num_total,
                "dwarf_reg_num_total":self.dwarf_reg_num_total,
                "dwarf_stack_num_total":self.dwarf_stack_num_total,
                "dwarf_poly_num_total":self.dwarf_poly_num_total,
                "dwarf_unknown_num_total":self.dwarf_unknown_num_total,
                "ans_ida_identified_num_total":self.ans_ida_identified_num_total

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

    dwarf_num = 0
    dwarf_none_num = 0
    dwarf_reg_num = 0
    dwarf_stack_num = 0
    dwarf_poly_num = 0
    dwarf_unknown_num = 0

    ans_ida_identified_num = 0



    def __init__(self,ifunc):
        self.func_name = ifunc['function_name']
        self.ida_num = ifunc['ida_num']
        self.ida_none_num = ifunc['ida_none_num']
        self.ida_has_dwarf = ifunc['ida_has_dwarf']
        self.ida_reg_num = ifunc['ida_reg_num']
        self.ida_stack_num = ifunc['ida_stack_num']
        pass
    
    def merge(self,dfunc):
        self.dwarf_num = dfunc['dwarf_num']
        self.dwarf_none_num = dfunc['dwarf_none_num']
        self.dwarf_reg_num = dfunc['dwarf_reg_num']
        self.dwarf_stack_num = dfunc['dwarf_stack_num']
        self.dwarf_poly_num = dfunc['dwarf_poly_num']
        self.dwarf_unknown_num = dfunc['dwarf_unknown_num']
        pass
    
    
    def add_ans_ida_identified_num(self,num):
        self.ans_ida_identified_num+=num
        pass

    
    def serialize(self,minfo):
        return minfo.add_func_info(
            self.func_name,
            self.ida_num,
            self.ida_none_num,
            self.ida_has_dwarf,
            self.ida_reg_num,
            self.ida_stack_num,
            self.dwarf_num,
            self.dwarf_none_num,
            self.dwarf_reg_num,
            self.dwarf_stack_num,
            self.dwarf_poly_num,
            self.dwarf_unknown_num,
            self.ans_ida_identified_num
        )


def find_dwarf_func(dfunc_list,fname):
    # search in dfunc_list
    candidates = [df for df in dfunc_list if df['function_name']==fname]
    # check number of candidates, must be 1
    assert len(candidates)<=1,"Error dwarf function number"
    return candidates[0]

def intersect_varlist(finfo,ilist,dlist):
    var_map={}
    for dl in dlist:
        var_map[dl['name']]=1
    for il in ilist:
        print(il)
        if il['name']==''  or il['hasdwarf']==False:
            continue
        # assert var_map[il['name']],"IDA must has symbol here"
        finfo.add_ans_ida_identified_num(1)
    pass 

def analysis(ijson_file,djson_file):
    print(ijson_file,djson_file)
    with open(ijson_file, 'rb') as ijson, open(djson_file, 'rb') as djson:
        ijson,djson = json.load(ijson),json.load(djson)
        ifunc_list,dfunc_list= ijson['FunctionInfo'],djson['FunctionInfo']

        minfo = ModuleInfo(ijson,djson)
        for ifunc in ifunc_list:
            finfo = FunctionInfo(ifunc)
            try:
                dfunc = find_dwarf_func(dfunc_list,finfo.func_name)
            except:
                print("[*] Cannot find function {} in dwarf".format(finfo.func_name))
                continue
            finfo.merge(dfunc)
            intersect_varlist(finfo,ifunc['var_list'],dfunc['var_list'])
            finfo.serialize(minfo)
        return minfo.serialize()
        

if __name__ == "__main__":
    # check file
    binary = sys.argv[1]
    ida_json_file,dwarf_json_file = binary+'.ida.json',binary+'.dwarf.json'
    with open('{}.ans.json'.format(binary), 'w+') as f:
        module_info=analysis(ida_json_file,dwarf_json_file)
        json.dump(module_info,f)




