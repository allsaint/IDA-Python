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

## set_cmt()

^0b69c2

```python
# Set comments on xrefs to all thunk functions
# if function is jmp to other function, set comment
import idautils
for func in Functions():
    flags = get_func_attr(func, FUNCATTR_FLAGS)
    if   flags & FUNC_LIB:
        continue
    for line in FuncItems(func):    
        disasm_addr = generate_disasm_line(line,0)
        op1 = print_operand(line,0)
        op2 = print_operand(line,1)
        mnem = print_insn_mnem(line)
        if  mnem == "jmp":
            if_thunk = get_operand_value(line,0)
            flag = get_func_attr(if_thunk,FUNCATTR_FLAGS)
            
            if flag & FUNC_THUNK and not flag & FUNC_LIB:
                
                for xref in XrefsTo(if_thunk,1):
                    if xref.iscode:
                        print(hex(xref.frm),generate_disasm_line(xref.frm,0))
                        print ( idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to))
                        set_cmt(xref.frm,"THUNK JMP FUNCTION",1)

''' [>_]
0x7ff75542939c jmp     j_free; THUNK JMP FUNCTION
Code_Near_Jump 0x7ff75542939c 0x7ff755429820
0x7ff755429820 jmp     free; THUNK JMP FUNCTION
Code_Near_Jump 0x7ff755429820 0x7ff75542a088
'''
```


```python
# а хуй знает че этот скрипт делает
def check_for_wrapper(func):
    flags = idc.get_func_attr(func, idc.FUNCATTR_FLAGS)
    if flags & idc.FUNC_LIB or flags & idc.FUNC_THUNK:
        return
    dism_addr = [x for x in idautils.FuncItems(func) ]
    dism_hex = [hex(x) for x in idautils.FuncItems(func) ]
    print(dism_hex)
    dism_len=0
    for x in idautils.FuncItems(func):
        dism_len+=1
    if dism_len > 0x20:
        return
    func_call = 0
    instr_cmp = 0
    op = None
    op_addr = None
    op_type = None
    for ea in dism_addr:
        m = idc.print_insn_mnem(ea)
        if m == 'call' or m == 'jmp':
            if m == 'jmp':
                temp = idc.get_operand_value(ea, 0)
                if temp in dism_addr:
                    print(hex(temp), idc.generate_disasm_line(temp,0))
            func_call += 1
            # wrappers should not contain multiple function calls
            op_addr = idc.get_operand_value(ea, 0)
            op_type = idc.get_operand_type(ea, 0)
        elif m == 'cmp' or m == 'test':
            # wrappers functions should not contain much logic.
            instr_cmp += 1
        else:
            continue
    print("[+] Total function calls: ",func_call)
    print("[+] Total compare instructions: ", instr_cmp)
check_for_wrapper(x)

''' [>_]
['0x7ff7554288b0', '0x7ff7554288b5', '0x7ff7554288b9', '0x7ff7554288be', '0x7ff7554288c3', '0x7ff7554288c8', '0x7ff7554288cd', '0x7ff7554288cf', '0x7ff7554288d7', '0x7ff7554288d9', '0x7ff7554288e1', '0x7ff7554288e6', '0x7ff7554288e9', '0x7ff7554288ed', '0x7ff7554288ef', '0x7ff7554288f1', '0x7ff7554288f6', '0x7ff7554288f9', '0x7ff7554288fe', '0x7ff755428903', '0x7ff755428908', '0x7ff75542890d', '0x7ff755428911']
0x7ff7554288e1 movzx   eax, byte ptr [rsp+28h+var_24]
[+] Total function calls:  1
[+] Total compare instructions:  2
'''

```