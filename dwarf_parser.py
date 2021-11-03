from __future__ import print_function
import sys

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
import json,re


class ModuleInfo:

    dwarf_num_total = 0
    dwarf_none_num_total = 0
    func_info_list = []

    def add_func_info(self,func_name,
                    dwarf_num,dwarf_none_num,var_list):

        self.dwarf_num_total+=dwarf_num
        self.dwarf_none_num_total+=dwarf_none_num
        return self.func_info_list.append({
            "function_name":bytes2str(func_name),
            "dwarf_num":dwarf_num,
            "dwarf_none_num":dwarf_none_num,
            "var_list":var_list
        })

    def serialize(self):
        return {
            "ModuleInfo":{
                "dwarf_num_total":self.dwarf_num_total,
                "dwarf_none_num_total":self.dwarf_none_num_total
            },
            "FunctionInfo":self.func_info_list
        }

class FunctionInfo:
    func_name=None
    dwarf_num = 0
    dwarf_none_num = 0
    var_list = []
    
    def set_func_name(self,name):
        self.func_name = name
    
    def get_func_name(self):
        return self.func_name
    
    def set_dwarf_num(self,num):
        self.dwarf_num = num
    
    def get_dwarf_num(self):
        return self.dwarf_num
    
    def set_dwarf_none_num(self,num):
        self.dwarf_none_num = num
    
    def get_dwarf_none_num(self):
        return self.dwarf_none_num
    
    def clear_var_list(self):
        self.var_list = []
    
    def add_var_info(self,vname,detail):
        self.var_list.append({
            "name":bytes2str(vname),
            "details":detail
        })
    
    def serialize(self,minfo):
        return minfo.add_func_info(
            self.func_name,
            self.dwarf_num,
            self.dwarf_none_num,
            self.var_list
        )

class DwarfParser:
    module_info = None
    function_info = None # tmp info
    elffile = None
    dwarfinfo = None
    location_lists = None
    loc_parser = None
    cu = None
    scope_layers = 0

    def __init__(self,filename):
        self.module_info = ModuleInfo()
        with open(filename, 'rb') as f:
            self.elffile = ELFFile(f)

            if not self.elffile.has_dwarf_info():
                print('  file has no DWARF info')
                return

            # get_dwarf_info returns a DWARFInfo context object, which is the
            # starting point for all DWARF-based processing in pyelftools.
            self.dwarfinfo = self.elffile.get_dwarf_info()

            # The location lists are extracted by DWARFInfo from the .debug_loc
            # section, and returned here as a LocationLists object.
            self.location_lists = self.dwarfinfo.location_lists()

            # This is required for the descriptions module to correctly decode
            # register names contained in DWARF expressions.
            set_global_machine_arch(self.elffile.get_machine_arch())

            # Create a LocationParser object that parses the DIE attributes and
            # creates objects representing the actual location information.
            self.loc_parser = LocationParser(self.location_lists)
    
    def cu_iterator(self):
        return self.dwarfinfo.iter_CUs()
    
    def set_cu(self,cu):
        self.cu = cu

    def parse_die_node(self,die):

        assert (self.scope_layers<=1), "nested function"
        try:
            print('DIE id=%s' % die.attributes['DW_AT_name'].value)
        except:
            pass
        
        if die.tag == 'DW_TAG_subprogram':
            # Cannot identify the end of function, 
            # so we have to complete the variables collection here
            # print(die.attributes['DW_AT_name'].value)
            self.__parse_func(die)
            return 
            # parse_func(die)
        if die.tag=="DW_TAG_variable":
            # End point
            self.__parse_variable(die)
            return
            # print(die.attributes['DW_AT_location'].form,die.attributes['DW_AT_name'].value)
        for child in die.iter_children():
            self.parse_die_node(child)


    def __enter_func(self):
        self.scope_layers+=1

    def __exit_func(self):
        self.scope_layers-=1

    def __parse_func(self,die):
        self.function_info = FunctionInfo()
        # enter the function
        self.__enter_func()

        try:
            self.function_info.set_func_name(die.attributes['DW_AT_name'].value)
        except:
            self.__exit_func()
            return
        for child in die.iter_children():
            self.parse_die_node(child)
        # exit the function
        # Only need one layer of varlist since there is no possiable for nested function
        self.__exit_func()

        self.function_info.serialize(self.module_info)
        return
    
    def __parse_variable(self,die):
        assert (self.scope_layers<=1), "nested function"
        try:
            name = die.attributes['DW_AT_name'].value
        except:
            print('[-] variable has no DW_AT_name',die.attributes)
            name = b""
            pass
        loc = self.__location(die)
        # Todo: add stack/reg check here
        if not loc:
            return
        elif not self.__check_local_variable(loc['loc_desc']):
            print('[+] Global Variable: %s' % name)
            return
        elif not self.scope_layers:
            raise RuntimeError('Local Variable Ignored',name)
        else:
            self.function_info.add_var_info(name,loc['loc_desc'])
        return 

    def __location(self,die):
        assert (die.tag=='DW_TAG_variable'), "not variable"

        try:
            loc = self.loc_parser.parse_from_attribute(
                die.attributes['DW_AT_location'],
                self.cu['version'])
        except:
            print('[-] There are no DW_AT_location in variable')
            return None
        if isinstance(loc, LocationExpr):
            ldesc = describe_DWARF_expr(loc.loc_expr,self.dwarfinfo.structs, self.cu.cu_offset)
        elif isinstance(loc, list):
            ldesc = self.__show_loclist(loc,self.dwarfinfo,self.cu.cu_offset)
        ltype = self.__location_type(ldesc)

        return {"loc_desc":ldesc,"loc_type":ltype}
    
    def __location_type(self,desc):
        # stack 
        # register
        # polymorphism
        # Need regular expressions to handle different instance type of desc
        return 'polymorphism'

    def __check_local_variable(self,desc):

        if  desc==None or 'DW_OP_addr' in desc:
            return False
        else:
        # elif 'DW_OP_addr' in desc or 'DW_OP_GNU_implicit_pointer' in desc:
            return True
        raise RuntimeError('Unknown describe_DWARF_expr',desc)

    def __show_loclist(self,loclist, dwarfinfo, cu_offset):
        """ Display a location list nicely, decoding the DWARF expressions
            contained within.
        """
        d = []
        for loc_entity in loclist:
            if isinstance(loc_entity, LocationEntry):
                d.append('%s <<%s>>' % (
                    loc_entity,
                    describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)))
            else:
                d.append(str(loc_entity))
        return '\n'.join(s for s in d)
    
    def top_die(self):
        top_DIE = self.cu.get_top_DIE()
        return top_DIE

    
def process_file(filename):
    print('Processing file:', filename)

    dp = DwarfParser(filename)
    
    for CU in dp.cu_iterator():
        dp.set_cu(CU)
        # DWARFInfo allows to iterate over the compile units contained in
        # the .debug_info section. CU is a CompileUnit object, with some
        # computed attributes (such as its offset in the section) and
        # a header which conforms to the DWARF standard. The access to
        # header elements is, as usual, via item-lookup.

        # Start with the top DIE, the root for this CU's DIE tree

        # Display DIEs recursively starting with top_DIE
        dp.parse_die_node(dp.top_die())
    return dp.module_info.serialize()


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        with open('{}.dwarf.json'.format(filename), 'w+') as f:
            module_info = process_file(filename)
            # print(module_info)
            json.dump(module_info,f)
        





