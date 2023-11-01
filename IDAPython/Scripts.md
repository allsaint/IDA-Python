[+] дебильный скрит ищет потворяющиеся функции в сете 
(сет по дефолту не содержит потворяющихся значений) 
```python
#print(hex(idc.get_segm_by_sel(idc.selector_by_name(".text"))))
#print(hex(idc.selector_by_name(".rsrc")))
import idautils
import idc 
import idaapi
duplicates = []
functions = []
for addr in idautils.Functions():
    if("sub_" in get_func_name(addr)):
        functions.append(addr)
print("Native functions complete!")

for id1, addr1 in enumerate (functions):
    for id2, addr2 in enumerate (functions): 
        if(get_func_name(addr1)==get_func_name(addr2) and id1!=id2 ):
            duplicates.append({hex(addr2):get_func_name(addr2)})
print("Duplicate functions complete!")
print("Here is the list: ", duplicates)

ea = here()
func = idaapi.get_func(ea)
type(func)
dir(func)
```


[+] If  second operand looks like address
```python
CALLS = [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]
import idautils

min = get_inf_attr(INF_MIN_EA)
max = get_inf_attr(INF_MAX_EA)

for func in Functions():
	flag= idc.get_func_attr(func, FUNCATTR_FLAGS)
	if flag & FUNC_LIB or flag & FUNC_THUNK:
		continue
	for line in FuncItems(func):
		op = get_operand_type(line,1)
		op_val = get_operand_value(line,1)
		instr_obj = ida_ua.insn_t()
		instr = idaapi.decode_insn(instr_obj,line)
		if op==o_imm and op_val>0xff :
			print(hex(line))
			print(generate_disasm_line(line,0))
print("done")

```