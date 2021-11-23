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


class cached_property(object):
    """
    Descriptor (non-data) for building an attribute on-demand on first use.
    """
    def __init__(self, factory):
        """
        <factory> is called such: factory(instance) to build the attribute.
        """
        self._attr_name = factory.__name__
        self._factory = factory

    def __get__(self, instance, owner):
        # Build the attribute.
        attr = self._factory(instance)

        # Cache the value; hide ourselves.
        setattr(instance, self._attr_name, attr)

        return attr

class ModuleInfo:
    func_num = 0
    inlined_num = 0
    declared_inlined_num = 0
    dwarf_num_total = 0
    dwarf_none_num_total = 0
    dwarf_reg_num_total = 0
    dwarf_stack_num_total = 0
    dwarf_poly_num_total = 0
    dwarf_unknown_num_total = 0
    func_info_list = []

    def add_func_info(self,func_name,inlined,declared_inlined,
                    dwarf_num,dwarf_none_num,
                    dwarf_reg_num,
                    dwarf_stack_num,
                    dwarf_poly_num,
                    dwarf_unknown_num,
                    var_list):
        
        self.func_num+=1

        if inlined:
            self.inlined_num+=1
        if declared_inlined:
            self.declared_inlined_num+=1

        self.dwarf_num_total+=dwarf_num
        self.dwarf_none_num_total+=dwarf_none_num
        self.dwarf_reg_num_total+=dwarf_reg_num
        self.dwarf_stack_num_total+=dwarf_stack_num
        self.dwarf_poly_num_total+=dwarf_poly_num
        self.dwarf_unknown_num_total+=dwarf_unknown_num

        return self.func_info_list.append({
            "function_name":bytes2str(func_name),
            "inlined":inlined,
            "declared_inlined":declared_inlined,
            "dwarf_num":dwarf_num,
            "dwarf_none_num":dwarf_none_num,
            "dwarf_reg_num":dwarf_reg_num,
            "dwarf_stack_num":dwarf_stack_num,
            "dwarf_poly_num":dwarf_poly_num,
            "dwarf_unknown_num":dwarf_unknown_num,
            "var_list":var_list
        })

    def serialize(self):
        return {
            "ModuleInfo":{
                "func_num":self.func_num,
                "inlined_num":self.inlined_num,
                "declared_inlined_num":self.declared_inlined_num,
                "dwarf_num_total":self.dwarf_num_total,
                "dwarf_none_num_total":self.dwarf_none_num_total,
                "dwarf_reg_num_total":self.dwarf_reg_num_total,
                "dwarf_stack_num_total":self.dwarf_stack_num_total,
                "dwarf_poly_num_total":self.dwarf_poly_num_total,
                "dwarf_unknown_num_total":self.dwarf_unknown_num_total
            },
            "FunctionInfo":self.func_info_list
        }

class FunctionInfo:
    func_name = None
    inlined = False
    declared_inlined = False

    dwarf_num = 0
    dwarf_none_num = 0
    dwarf_reg_num = 0
    dwarf_stack_num = 0
    dwarf_poly_num = 0
    dwarf_unknown_num = 0
    var_list = []

    def __init__(self):
        self.func_name = None
        self.inlined = False
        self.declared_inlined = False

        self.dwarf_num = 0
        self.dwarf_none_num = 0
        self.dwarf_reg_num = 0
        self.dwarf_stack_num = 0
        self.dwarf_poly_num = 0
        self.dwarf_unknown_num =0
        self.var_list = []

    def set_func_name(self,name):
        self.func_name = name
    
    def set_inlined(self):
        self.inlined = True
    
    def set_declared_inlined(self):
        self.declared_inlined = True


    def __add_dwarf_reg_num(self):
        self.dwarf_reg_num+=1
    
    def __add_dwarf_stack_num(self):
        self.dwarf_stack_num+=1
    
    def __add_dwarf_poly_num(self):
        self.dwarf_poly_num+=1
    
    def __add_dwarf_unknown_num(self):
        self.dwarf_unknown_num+=1
    
    def __statistics(self,vname,ltype):
        self.dwarf_num+=1
        if bytes2str(vname)=="":
            self.dwarf_none_num+=1
            # Just return with no further handle of variable type
            return 
        # assert (ltype!="None"),"Dwarf variable is neither in STACK nor in REGISTER"
        return {
            "None": (self.__add_dwarf_unknown_num),
            "Reg": (self.__add_dwarf_reg_num),
            "Stack": (self.__add_dwarf_stack_num),
            "Poly": (self.__add_dwarf_poly_num)
        }[ltype]()
    
    def add_var_info(self,vname,detail,ltype):
        self.__statistics(vname,ltype)
        self.var_list.append({
            "name":bytes2str(vname),
            "details":detail,
            "type":ltype
        })
    
    def serialize(self,minfo):
        return minfo.add_func_info(
            self.func_name,
            self.inlined,
            self.declared_inlined,
            self.dwarf_num,
            self.dwarf_none_num,
            self.dwarf_reg_num,
            self.dwarf_stack_num,
            self.dwarf_poly_num,
            self.dwarf_unknown_num,
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

    def __enter_func(self):
        self.scope_layers+=1

    def __exit_func(self):
        self.scope_layers-=1

    def __parse_func(self,die):
        self.function_info = FunctionInfo()
        # enter the function
        self.__enter_func()

        name = self.__get_attribute_value_recursive(die,'DW_AT_name')
        self.function_info.set_func_name(name)

        if name==None:
            self.__exit_func()
            return

        # check if this function is inlined or not
        if self.__is_inlined(die):
            self.function_info.set_inlined()
        if self.__declared_inline(die):
            self.function_info.set_declared_inlined()

        for child in die.iter_children():
            self.parse_die_node(child)
        # exit the function
        # Only need one layer of varlist since there is no possiable for nested function
        self.__exit_func()

        self.function_info.serialize(self.module_info)
        return
    
    def __parse_variable(self,die):
        assert (self.scope_layers<=1), "nested function"
        # try:
        #     name = die.attributes['DW_AT_name'].value
        # except:
        #     print('[-] variable has no DW_AT_name',die.attributes)
        #     name = b""
        #     pass
        name = self.__get_attribute_value_recursive(die,'DW_AT_name')
        if name==None:
            # print('[-] variable has no DW_AT_name',die.attributes)
            name = b""
            pass

        loc = self.__location(die)
        # Todo: add stack/reg check here
        if not loc:
            return
        elif not self.__check_local_variable(loc['loc_desc']):
            # print('[+] Global Variable: %s' % name)
            return
        elif not self.scope_layers:
            raise RuntimeError('Local Variable Ignored',name)
        else:
            self.function_info.add_var_info(name,loc['loc_desc'],loc['loc_type'])
        return 

    def __location(self,die):
        assert (die.tag=='DW_TAG_variable'), "not variable"

        try:
            loc = self.loc_parser.parse_from_attribute(
                self.__get_attribute_recursive(die,'DW_AT_location'),
                self.cu['version'])
        except:
            print('[-] There are no DW_AT_location in variable',die)
            return None

        if isinstance(loc, LocationExpr):
            ldesc = describe_DWARF_expr(loc.loc_expr,self.dwarfinfo.structs, self.cu.cu_offset)
        elif isinstance(loc, list):
            ldesc = self.__show_loclist(loc,self.dwarfinfo,self.cu.cu_offset)
        ltype = self.__location_type(ldesc)

        return {"loc_desc":ldesc,"loc_type":ltype}
    
    def __location_type(self,desc):
        ref = 0
        if 'DW_OP_reg' in desc:
            ref = ref | 1
        if 'DW_OP_fbreg' in desc:
            ref = ref | 2
        data=['None','Reg',"Stack","Poly"]
        return data[ref]

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
                d.append('<<%s>>' % (
                    describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs, cu_offset)))
            else:
                d.append(str(loc_entity))
        return '\n'.join(s for s in d)

    def __get_die_at_offset(self, cu, offset):
        adjusted_offset = cu.cu_offset + offset
        for die in cu.iter_DIEs():
            if die.offset == adjusted_offset:
                return die

    def __get_attribute_value(self, die, attribute):
        attr = die.attributes.get(attribute)
        if attr is not None:
            return attr.value

    def __specification(self,die):
        # TODO: Handle all types of references
        offset = self.__get_attribute_value(die, 'DW_AT_specification')
        if not offset:
            return None
        spec = self.__get_die_at_offset(die.cu, offset)
        if spec:
            return spec
        else:
            print('WARNING: No die at offset', offset)

    def __get_attribute_recursive(self, die, name):
        attribute = die.attributes.get(name, None)
        if attribute:
            return attribute
        spec = self.__specification(die)
        if spec:
            return self.__get_attribute_recursive(spec,name)
        return None

    def __get_attribute_value_recursive(self, die, name):
        attr = self.__get_attribute_recursive(die,name)
        if attr:
            return attr.value
        else:
            return None

    @cached_property
    def top_die(self):
        top_DIE = self.cu.get_top_DIE()
        return top_DIE

    def __inline_enum(self,die):
        assert (die.tag=='DW_TAG_subprogram'), "not subprogram"
        return self.__get_attribute_value_recursive(die,'DW_AT_inline') or 0

    def __is_inlined(self,die):
        assert (die.tag=='DW_TAG_subprogram'), "not subprogram"
        return self.__inline_enum(die) in (1, 3)

    def __declared_inline(self,die):
        assert (die.tag=='DW_TAG_subprogram'), "not subprogram"
        return self.__inline_enum(die) in (2, 3)

    def cu_iterator(self):
        return self.dwarfinfo.iter_CUs()
    
    def set_cu(self,cu):
        self.cu = cu

    def parse_die_node(self,die):

        assert (self.scope_layers<=1), "nested function"

        # print(self.__get_attribute_value_recursive(die,'DW_AT_name'))
        
        if die.tag == 'DW_TAG_subprogram':
            # Cannot identify the end of function, 
            # so we have to complete the variables collection here
            # print(die.attributes['DW_AT_name'].value)
            self.__parse_func(die)
            return 
            # parse_func(die)
        if die.tag == "DW_TAG_variable":
            # End point
            self.__parse_variable(die)
            return
            # print(die.attributes['DW_AT_location'].form,die.attributes['DW_AT_name'].value)
        for child in die.iter_children():
            self.parse_die_node(child)

    
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
        dp.parse_die_node(dp.top_die)
    return dp.module_info.serialize()


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        with open('{}.dwarf.json'.format(filename), 'w+') as f:
            module_info = process_file(filename)
            # print(module_info)
            json.dump(module_info,f)
        





