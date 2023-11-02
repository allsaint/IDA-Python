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

## bin_search()

^fcd573

```python 
# find specific byte pattern
import ida_bytes
print("\n\n\n=== START ===\n")

patterns = ["48 3D 9C 07 08 0C", "E8 12 EE FF FF", "80 3C 08 00", "45 33 C0"]
image_base = idaapi.get_imagebase()

min= idc.get_inf_attr(INF_MIN_EA)
max= idc.get_inf_attr(INF_MAX_EA)

for pattern_str in patterns:
	pattern_compiled = ida_bytes.compiled_binpat_vec_t()
	err = ida_bytes.parse_binpat_str(pattern_compiled,image_base, pattern_str ,16)
	if addr == idc.BADADDR:
		print("error")
	address = ida_bytes.bin_search(min, max, pattern_compiled, ida_bytes.BIN_SEARCH_FORWARD)
	print(hex(address))

print("\n=== END ===\n\n\n")
```

## find_text()

^93ecf0

```python
# Find string
print("\n\n=== START ===\n")

start = idc.get_inf_attr(INF_MIN_EA)
end = idc.get_inf_attr(INF_MAX_EA)
while start< end:
	start = idc.find_text(start, SEARCH_DOWN, 0, 0, "MSVCP140.dll")
	if start == idc.BADADDR:
		break
	else:
		print (hex(start), idc.generate_disasm_line(start, 0))
	start = idc.next_head(start)

print("\n=== END ===\n\n")
```

## read_selection()

^3a6e55

```python
p0 = idaapi.twinpos_t()
p1 = idaapi.twinpos_t()
view = idaapi.get_current_viewer()
err = idaapi.read_selection(view, p0, p1)

place0 = p0.place(view)
place1 = p1.place(view)

# Output 'from' and 'to' of selected adress range
print(hex(place0.ea), hex(place1.ea))

''' [>_]
0x7ff74fe025b1
0x7ff74fe025e9
'''
```