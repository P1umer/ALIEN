from __future__ import print_function
import sys

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']
var_number = 0


from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
import json,re


scope_layers=0
varlist = []
func_list=[]

loc_parser=None
dwarfinfo=None
cu=None

desc=None
func_name=None



def process_file(filename):
    global loc_parser,cu,dwarfinfo
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            return

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        # The location lists are extracted by DWARFInfo from the .debug_loc
        # section, and returned here as a LocationLists object.
        location_lists = dwarfinfo.location_lists()

        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(elffile.get_machine_arch())

        # Create a LocationParser object that parses the DIE attributes and
        # creates objects representing the actual location information.
        loc_parser = LocationParser(location_lists)

        for CU in dwarfinfo.iter_CUs():
            cu = CU
            # DWARFInfo allows to iterate over the compile units contained in
            # the .debug_info section. CU is a CompileUnit object, with some
            # computed attributes (such as its offset in the section) and
            # a header which conforms to the DWARF standard. The access to
            # header elements is, as usual, via item-lookup.
            print('  Found a compile unit at offset %s, length %s' % (
                CU.cu_offset, CU['unit_length']))

            # Start with the top DIE, the root for this CU's DIE tree
            top_DIE = CU.get_top_DIE()
            top_DIE.__repr__()
            print('    Top DIE with tag=%s' % top_DIE.tag)
            # We're interested in the filename...
            print('    name=%s' % top_DIE.get_full_path())

            # Display DIEs recursively starting with top_DIE
            parse_die_node(top_DIE)

def show_loclist(loclist, dwarfinfo, cu_offset):
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
    


def json_serialize(fname,vlist):
    global func_list
    return func_list.append({
        "function_name":bytes2str(fname),
        "var_list":vlist,
    })


def parse_func(die,indent_level):
    global scope_layers,varlist,func_name
    # enter the function
    scope_layers+=1

    try:
        func_name = die.attributes['DW_AT_name'].value
    except:
        scope_layers-=1
        varlist=[]
        return

    # parse child nodes
    child_indent = indent_level + '  '
    for child in die.iter_children():
        parse_die_node(child, child_indent)
    # exit the function
    scope_layers-=1

    json_serialize(func_name,varlist)

    # clear the varlist
    # Only need one layer of varlist since there is no possiable for nested fucntion
    varlist=[]
    return 
    


def check_local_variable(die):
    global loc_parser,cu,dwarfinfo,desc,func_name
    
    assert (die.tag=='DW_TAG_variable'), "not variable"
    try:
        loc = loc_parser.parse_from_attribute(
            die.attributes['DW_AT_location'],
            cu['version'])
    except:
        print('[-] There are no DW_AT_location in variable %s of function %s'%(
            "error",#die.attributes['DW_AT_name'].value,
            func_name))
        return False
    if isinstance(loc, LocationExpr):
        desc = describe_DWARF_expr(loc.loc_expr,dwarfinfo.structs, cu.cu_offset)
    elif isinstance(loc, list):
        desc = show_loclist(loc,dwarfinfo,cu.cu_offset)

    if 'DW_OP_addr' in desc:
        return False
    else:
    # elif 'DW_OP_addr' in desc or 'DW_OP_GNU_implicit_pointer' in desc:
        return True
    raise RuntimeError('Unknown describe_DWARF_expr',desc)



def parse_variable(die):
    global scope_layers,varlist,desc
    assert (scope_layers<=1), "nested function"
    try:
        name = die.attributes['DW_AT_name'].value
    except:
        print('[-] variable has no DW_AT_name',die.attributes)
        name = b""
        pass
    if not check_local_variable(die):
        print('[+] Global Variable: %s' % name)
        return
    elif not scope_layers:
        raise RuntimeError('Local Variable Ignored',name)
    else:
        varlist.append({
            "name":bytes2str(name),
            "details":desc
        })
    return 


def parse_die_node(die, indent_level='    '):
    print(indent_level + 'DIE tag=%s' % die.tag)
    # if indent_level == '    '+'  '+'  ':
    #     return

    try:
        print(indent_level + 'DIE id=%s' % die.attributes['DW_AT_name'].value)
    except:
        pass
    
    if die.tag == 'DW_TAG_subprogram':
        # Cannot identify the end of function, 
        # so we have to complete the variables collection here
        # print(die.attributes['DW_AT_name'].value)
        parse_func(die,indent_level)
        return 
        # parse_func(die)
    if die.tag=="DW_TAG_variable":
        # End point
        parse_variable(die)
        return
        # print(die.attributes['DW_AT_location'].form,die.attributes['DW_AT_name'].value)
    
    child_indent = indent_level + '  '
    for child in die.iter_children():
        parse_die_node(child, child_indent)

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        with open('{}.dwarf.json'.format(filename), 'w+') as f:
            process_file(filename)
            json.dump(func_list,f)
        
        