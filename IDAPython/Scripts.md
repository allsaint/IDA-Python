[+] дебильный скрит ищет дубликаты функций в сете 
(сет по дефолту содержит только уникальные значения) 
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