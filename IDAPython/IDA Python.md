# Functions

```python
# minimum address that is present in an IDB 
idc.get_inf_attr(INF_MIN_EA)
# maximum address that is present in an IDB 
idc.get_inf_attr(INF_MAX_EA)
# get segment name by address
idc.get_segm_name(ea) 
```

```python
# 0 - get 1st operand, 1 - get 2nd operand
if (idc.print_operand(here(),0) =="rbp"):
	print("true")
```

```python
# get disasssembly of the line at address ea
# 0 disassemle, 1 ignore IDA disassembly
idc.generate_disasm_line(ea, 0)
```

```python
# get list of all functions
idautils.Functions()
# get list in range of two addresses
idautils.Functions(start_addr, end_addr)
```

``` python
# get function boundaries
func = idaapi.get_func(ea)
# get class members
print(dir(class))

# [!] func is a class of type idaapi.func_t
```

[+] Get next / previous function
```python
# get next function
idc.get_next_func(ea)
# get previous function
idc.get_prev_func(ea).
# [!] ea needs to be within the boundaries of the analyzed function
```


```python
# Code that is not marked as a function is labeled red in the legend 
# These can be manually fixed or automated using the function
idc.create_insn(ea)
```
# Function attributes

[+] Iterating through instructions in a function
[+] Usage of `idautils.FuncItems()` function 
[+] Usage of `idc.get_func_attr()` function 
[+] Usage of `idc.next_head()` function 
``` python
# 1. Loop through instructions in function
# [!] Unreliable: if there is jump in func, it will be taken
current_address = idc.get_func_attr(ea, FUNCATTR_START)
end_address = idc.get_func_attr(ea, FUNCATTR_END)
while( current_address <= end_address):
	print(hex(current_address), generate_disasm_line(current_address, 0))
	current_address = idc.next_head(current_address, end_address)

# 2. Loop through instructions in function
# [+] Reliable
for line in idautils.FuncItems(func):
	print(hex(line) , generate_disasm_line(line,0))
	
idc.get_func_attr(ea, FUNCATTR_START) 
idc.get_func_attr(ea, FUNCATTR_END)

# Get next instruction
ea = next_head(ea)
# Get next address 
ea = next_addr(ea)
```
# Function flags

[+] Function flags
[+] Usage of `idautils.Functions()` function 
```python
idc.get_func_attr(ea, FUNCATTR_FLAGS) # function flags (total - 9)

# Check function for flag correspondence
for func in idautils.Functions():
    flags = idc.get_func_attr(func,FUNCATTR_FLAGS)
    #function does not have a return value
    if (flags and FUNC_NORET): 
        print (hex(func), "FUNC_NORET") 
    if (flags and FUNC_FAR) :
        print (hex(func), "FUNC_FAR")
    if (flags and FUNC_LIB):
        print (hex(func), "FUNC_LIB")
    if (flags and FUNC_STATIC):
        print (hex(func), "FUNC_STATIC")
    if (flags and FUNC_FRAME):
        print (hex(func), "FUNC_FRAME")
    if (flags and FUNC_USERFAR):
        print (hex(func), "FUNC_USERFAR")
    if (flags and FUNC_HIDDEN):
        print (hex(func), "FUNC_HIDDEN")
    if (flags and FUNC_THUNK):
        print (hex(func), "FUNC_THUNK")
    if (flags and FUNC_LIB):
        print (hex(func), "FUNC_BOTTOMBP")
```


# Instructions

[+] Get dynamic calls inside all functions. (i.e. `call eax`, `jmp edi` etc. )
[+]Usage of `idaapi.decode_insn()` function 
```python 
JUMPS = [idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni]
CALLS = [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]

for func in Functions():
	#get flags of function 
	flags = get_func_attr(func, FUNCATTR_FLAGS)
	#if function is a jump to function (they are called thunk)
	#or if function is from library (i.e. __exit, __alloca_probe etc)
	if flags == FUNC_THUNK or flags == FUNC_LIB:
		continue
	for line in idautils.FuncItems(func):	
		#initialize class used for work with instructions
		instr_obj = ida_ua.insn_t()
		# decode instruction at line
		instr = idaapi.decode_insn(instr_obj,line) 
		#if instruction is of type JMP or CALL
		if instr_obj.itype in JUMPS or instr_obj.itype in CALLS:
			#if 1st operand is REGISTER
			if instr_obj.Op1.type == o_reg:
				print(generate_disasm_line(line,0))
print("=== Done! ====")

# [!] Working with the integer representation of the instruction can be faster and less error prone, 
# [!] decode_insn() needs 2 aruments: instructions class and address integer
```

[+] Usage `idc.get_operand_value()`
[+] Usage `idc.op_plain_offset()`
```python
idc.op_plain_offset(ea, n, base) #to convert the operand to an offset
idc.get_operand_value(ea, n)
idc.OpOff(curr_addr, 0, 0)
# n operand index
# ea offset
# base - base address
```


# Operands

[?] Operands are values going after instruction.
	Example: `mov eax, dword_4201488`
	instruction:  `mov`
	1st operand: `eax`
	2nd operand: `dword_4201488`

```python
def dis():
	print(idc.generate_disasm_line(here(), 0))
def op1():
	return print_operand(here(),0)
print("=== Start! ===")

ea= here()
func = idaapi.get_func(ea)
op_type=get_operand_type(here(),0)

if op_type ==o_void:
	print("o_void =", op1())
if op_type ==o_reg:
	print("o_reg =",op1())
if op_type ==o_mem:
	print("o_mem =", op1())
if op_type ==o_phrase:
	print("o_phrase =", op1())
if op_type ==o_displ:
	print("o_displ =", op1())
if op_type ==o_imm:
	print("o_imm =", op1())
if op_type ==o_far:
	print("o_far =" , op1())
if op_type ==o_near:
	print("o_near =", op1())

print("=== Done! ====")

```

# Xrefs To / Xrefs From
[?] Show cross references 'from' and 'to' of specific address

[+]Usage `idc.get_name_ea_simple()`
[+]Usage `idautils.CodeRefsTo()`
[+] `idautils.Names()` 
```python 
import idautils
print("=== Start! ===")
min = get_inf_attr(INF_MIN_EA)
max = get_inf_attr(INF_MAX_EA)
# Get function addr (.idata)
wf_addr = idc.get_name_ea_simple("IsDebuggerPresent")
# Get list of xrefs to function
# 2nd arg - bool flow. Follow normal code flow or not
for ref in idautils.CodeRefsTo(wf_addr,0):
	print(hex(ref), get_segm_name(ref))
	print(generate_disasm_line(ref,0))

# All renamed functions and APIs in an IDB can be accessed by calling idautils.Names()

```

```python 
ea = 0x10004932
print (hex(ea), idc.generate_disasm_line(ea, 0))

for addr in idautils.CodeRefsFrom(ea, 0):
	print (hex(addr), idc.generate_disasm_line(addr, 0))

''' [>_]
0x10004932 call ds:WriteFile
0x1000e1b8 extrn WriteFile:dword
'''
```


[+] Usage `idautils.DataRefsTo()`
[+] Usage `idautils.DataRefsFrom()`
```python
print("=== Start! ===")

print("From:")
ea = 0x00007FF75BD09C90
print(generate_disasm_line(ea,0))
for addr in DataRefsFrom(ea):
    print(hex(addr))
    
print("To:")
ea= 0x00007FF75BD0B000
print(generate_disasm_line(ea,0))
for addr in DataRefsTo(ea):
    print(hex(addr))   
print("=== Done! ====")

''' [>_]
=== Start! ===
From:
call    cs:IsDebuggerPresent
0x7ff75bd0b000
To:
dq offset kernel32_IsDebuggerPresent
0x7ff75bd09c90
0x7ff75bd0c7bc
=== Done! ====
'''
```

```python
# rename function manually
idc.set_name(ea, "RtlCompareMemory", SN_CHECK)
```

The following script collects all cross references to and from two particular addresses.
The script shows difference between passing argument 0 or 1 to `XrefsFrom`, `XrefsTo`

[+] `XrefsTo()`
[+] `xref.type` - 12 different documented reference type values
[+] `XrefTypeName(xref.type)`
[+] `xref.frm` 
[+] `xref.to` 
[+] `xref.iscode` - if the xref is in a code segment
```python
import idautils
import idaapi
import idc

print(" === START === ")

xref_from = set([])
xref_to = set([])

print("=== From - 0 ===")
# .text:...9C90 call    cs:IsDebuggerPresent
ea = 0x00007FF75BD09C90
for xref in XrefsFrom(ea,0):
	print (xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to), xref.iscode)

print("=== From - 1 ===")
for xref in XrefsFrom(ea,1):
	xrefs_from.add(hex(xref.frm))
	print (xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to), xref.iscode)

print("=== To - 0 ===")
# .idata:...B000 IsDebuggerPresent dq offset kernel32_IsDebuggerPresent
ea = 0x00007FF75BD0B000
# If the flag is 0 any cross reference are displayed
for xref in XrefsTo(ea,0):
	print (xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to), xref.iscode)

print("=== To - 1 ===")
# If the flag is 1 Ordinary_Flow reference types won't be displayed
for xref in XrefsTo(ea,1):
	xrefs_to.add(hex(xref.frm))
	print (xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to), xref.iscode)

# returns set
print("SET OF XREFS FROM: ",xrefs_from)
print("SET OF XREFS TO: ", xrefs_to)

# returns list
[x for x in xrefs_from]
[x for x in xrefs_to]

''' [>_]

=== From - 0 ===
21 Ordinary_Flow 0x7ff75bd09c90 0x7ff75bd09c96 1
17 Code_Near_Call 0x7ff75bd09c90 0x7ff75bd0b000 1
3 Data_Read 0x7ff75bd09c90 0x7ff75bd0b000 0

=== From - 1 ===
17 Code_Near_Call 0x7ff75bd09c90 0x7ff75bd0b000 1
3 Data_Read 0x7ff75bd09c90 0x7ff75bd0b000 0

=== To - 0 ===
17 Code_Near_Call 0x7ff75bd09c90 0x7ff75bd0b000 1
3 Data_Read 0x7ff75bd09c90 0x7ff75bd0b000 0
1 Data_Offset 0x7ff75bd0c7bc 0x7ff75bd0b000 0

=== To - 1 ===
17 Code_Near_Call 0x7ff75bd09c90 0x7ff75bd0b000 1
3 Data_Read 0x7ff75bd09c90 0x7ff75bd0b000 0
1 Data_Offset 0x7ff75bd0c7bc 0x7ff75bd0b000 0

SET OF XREFS FROM:  {'0x7ff75bd09c90'}
SET OF XREFS TO:  {'0x7ff75bd09c90', '0x7ff75bd0c7bc'}
'''


'''
[!] Cross references do not have to be caused by branch instructions. They can also be caused by normal ordinary code flow. If we set the flag to 1 Ordinary_Flow reference types won't be added.
'''


```
## Reference type values

	0 = 'Data_Unknown'
	1 = 'Data_Offset'
	2 = 'Data_Write'
	3 = 'Data_Read'
	4 = 'Data_Text'
	5 = 'Data_Informational'
	16 = 'Code_Far_Call'
	17 = 'Code_Near_Call'
	18 = 'Code_Far_Jump'
	19 = 'Code_Near_Jump'
	20 = 'Code_User'
	21 = 'Ordinary_Flow'


# Searching

[!] Python `idc.find_binary(ea, flag, searchstr, radix=16)` is deprecated.
Now `ida_bytes.bin_search(start_ea, end_ea, data, flags)` is used.
[?] Search for a set of bytes in the program

**ida_bytes.bin_search(start_ea, end_ea, data, flags)**
	`start_ea`:  start address of search
	`end_ea`: end address of search
	`data`:  data to search for (output from `parse_binpat_str()`)
	`flags`: combination of `BIN_SEARCH_*` flags
	_return_: the address of a match, or `ida_idaapi.BADADDR` if not found
[[Scripts#^fcd573|bin_search()]]

**parse_binpat_str(out, ea, \_in, radix, strlits_encoding=0)**
	`out`: a vector of compiled binary patterns, for use with bin_search()
	`ea`:  linear address to convert for (the conversion depends on the address, because the number of bits in a byte depend on the segment type)
	`in`:  input text string
	`radix`:  numeric base of numbers (8,10,16)
	`strlits_encoding`: the target encoding into which the string literals from 'in', should be encoded. Range from \[1, `get_encoding_qty()`\].
	`return`: false either in case of parsing error, or if at least one requested target encoding couldn't encode the string literals present in "in".
[[Scripts#^93ecf0|find_text()]]


``` python
# Check if specific address flagged ad code, data etc.
ea = here()
f =idc.get_full_flags(ea)
idc.is_code(f)
idc.is_data(f)
idc.is_tail(f)
idc.is_unknown(f)
idc.is_head(f)
```

```python
	ea = here()
	
	addr = idc.find_code(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
	print (hex(addr), idc.generate_disasm_line(addr, 0))
	
	addr = idc.find_data(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
	print (hex(addr), idc.generate_disasm_line(addr, 0))
	
	addr = idc.find_unknown(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
	print (hex(addr), idc.generate_disasm_line(addr, 0))
	
	addr = idc.find_defined(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
	print (hex(addr), idc.generate_disasm_line(addr, 0))
	
	
	# find_imm() returns tuple [address, operand]
	addr = idc.find_imm(get_inf_attr(INF_MIN_EA), SEARCH_DOWN, 0x134B2BF )
	print(hex(addr[0]), generate_disasm_line(addr[0],1))
```

```python 
ea = here()
print (hex(ea), idc.generate_disasm_line(ea, 0))
while(ea!= ida_idaapi.BADADDR):
	ea = idc.find_defined(ea, idc.SEARCH_DOWN )
	print (hex(ea), idc.generate_disasm_line(ea, 0))
	ea = next_head(ea)

'''[>_]
0x7ff74fe0d662 align 8
0x7ff74fe0d680 _onexit_table_t <0FFFFFFFFFFFFFFFFh, 0FFFFFFFFFFFFFFFFh, 0FFFFFFFFFFFFFFFFh>
0x7ff74fe0d6b8 dd 0
...
`__scrt_common_main_seh(void)'::`1'::filt$0
0x7ff74fe0e3a8 align 1000h
0xffffffffffffffff 
'''
```

# Selecting Data

[!] Note: you **MUST** select specific region in IDA by right clicking and dragging cursor till the needed addres region in IDA.
[?] Read the user selection, and store its information in p0 (from) and p1 (to).

**idc.read_selection()**
	`view`: The view to retrieve the selection for.
	`p0`: Storage for the "to" part of the selection.
	`p1`: Storage for the "to" part of the selection.
	**return**: a bool value indicating success.
[[Scripts#^3a6e55|read_selection()]]

# Comments & Renaming

**idc.set_cmt(ea, comment, is_repeatable)**
	`ea`: address of comment
	`comment`: comment itself
	`is_repeatable`: if comment is repeated throught the code. Value is either 0 or 1.
[[Scripts#^0b69c2|set_cmt()]]


**idc.set_name(ea, name, SN_CHECK)**
**idc.get_func_name(ea)**
**idc.get_operand_value(ea, n)**


# Accessing Raw Data

	idc.get_wide_byte(ea)
	idc.get_wide_word(ea)
	idc.get_wide_dword(ea)
	idc.get_qword(ea)
	idc.GetFloat(ea)
	idc.GetDouble(ea)

```python
ea = idc.here()
print (hex(ea), idc.generate_disasm_line(ea, 0))
print(hex (idc.get_wide_byte(ea)))
print(hex(idc.get_wide_word(ea)))
print(hex(idc.get_wide_dword(ea)))
print(hex(idc.get_qword(ea)))
print(idc.GetFloat(ea)) # Example not a float value
print(idc.GetDouble(ea))

''' [>_]
0x7ff7554288e1 movzx   eax, byte ptr [rsp+28h+var_24]
0xf
0xb60f
0x2444b60f
0x240488042444b60f
4.265493478866881e-17
3.5309265505939453e-135
'''


```

	idc.get_bytes(ea, size, use_dbg=False)

# Patching

**idc.patch_byte(ea, value)**
**idc.patch_word(ea, value)**
**idc.patch_dword(ea, value)**
	`ea`:  address of value
	`value`:  value to be set
[[#^996afe|patch_byte()]]

_Before patching:_
![[before.png]]
_After patching:_
![[after.png]]
# Input and Output

`ida_kernwin.ask_file(forsave, mask, prompt)`
forsave: can be a value of 0 if we want to open a dialog box or 1 is we want to open the save dialog box mask: is the file extension or pattern ( "\*.dll", "\*.py*")
# Intel Pin Logger

In progress...
# Batch File Generation

```python
import os
import subprocess
import glob
paths = glob.glob("*")
ida_path = os.path.join(os.environ['UserProfile'], "Desktop\IDA Pro 7.7", "idat.exe")
print(paths)
print(ida_path)
for file_path in paths:
    if file_path.endswith(".py"):
        continue
subprocess.call([ida_path, "-B", file_path])
'''[>_]
['crackme.exe', 'crackme.exe - Copy.i64', 'crackme.exe.i64', 'crackme.exe.id0', 'crackme.exe.id1', 'crackme.exe.id2', 'crackme.exe.nam']
C:\Users\saint\Desktop\IDA Pro 7.7\idat.exe
'''
```

# Executing Scripts
#
``` python 
idaapi.autoWait()
# python code
idc.Exit(0)
```

# Notes
[[Notes#^0a709d|Deprecated modules in idaapi]]

# Constants
```python
o_reg # register
```
# Refferences 

https://www.hex-rays.com/products/ida/support/idapython_docs/ida_bytes.html#ida_bytes.BIN_SEARCH_FORWARD
https://hex-rays.com/products/ida/support/idapython_docs/ida_search.html#ida_search.find_code
https://www.hex-rays.com/products/ida/support/idapython_docs/ida_kernwin.html

