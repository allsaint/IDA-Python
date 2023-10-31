
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
print("Done!")

# [!] Working with the integer representation of the instruction can be faster and less error prone, 
# [!] decode_insn() needs 2 aruments: instructions class and address integer
```


# Notes
[[Notes#^0a709d|Deprecated modules in idaapi]]

# Constants
```python
o_reg # register
```