# ALIEN: idA Local varIables rEcogNizer
`ALIEN` is an IDA Pro plugin that allows the user to get more information about ida local variables with the help of corresponding `DWARF` information.

## Usage
```
python3 dwarf_parser.py <path_of_the_ELF>
```
This script will analysis the DWARF information of the given ELF file, and will produce `.dwarf.json` file contains the analytical result in the same folder.
```
<path_of_idat/idat64> -A -c -S"ida_parse_f5.py" <path_of_the_ELF>
```
This IDA-python script will produce `.ida.json` file contains the analytical result of IDA in the same folder.
```
python3 analysis.py <path_of_the_ELF>
```
If you run the first two steps and successfully get `.dwarf.json` as well as `.ida.json` file, then this `analysis.py` script will perform comprehensive analysis of these two. The result will be stored in `.ans.json` file.
