IdaPython consists of three main modules
	- idc
	- idautills
	- idaapi

## Deprecated modules in `idaapi`

^0a709d

`cmd` doesn't exist in 7.5, use `insn_t()`.
replace `idaapi.cmd.Operands` with `idaapi.insn_t().ops`
