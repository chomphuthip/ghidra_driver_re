#consumers.py
#use when you have access to DLLs that use the driver

#get all calls of DeviceIoControl
#check what is stored in edx before call

from __future__ import print_function
import json
from ghidra.program.model.symbol import SourceType
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.util.datastruct import ListAccumulator

def find_param_load_by_ins(addr, mnem, op, op_index, back = 0):
    ins = getInstructionAt(addr)
    print('find_param_load_by_ins: ', ins)
    if ins.getDefaultOperandRepresentation(op_index) == op and ins.getMnemonicString() == mnem:
        return addr
    else:
        back = back + 1
        if back == 100:
            return None
        return find_param_load_by_ins(getInstructionBefore(addr).getAddress(), mnem, op, op_index, back)


symbol_table = currentProgram.getSymbolTable()

#returns an iterrator that points to the next symbol
imported_symbols = symbol_table.getExternalSymbols()

dev_io_ctrl_symbol = None
for imported_symbol in imported_symbols:
    if imported_symbol.getName() == u'DeviceIoControl':
        dev_io_ctrl_symbol = imported_symbol

if dev_io_ctrl_symbol == None:
    print('PE doesn\'t import DeviceIoControl')

dev_io_ctrl_refs = dev_io_ctrl_symbol.getReferences()

func_to_ioctl = {}
func_name_to_ioctl = {}

for ref in dev_io_ctrl_refs:
    if ref.getReferenceType().getName() == u'DATA':
        continue
    load_into_edx = find_param_load_by_ins(ref.getFromAddress(), u'MOV', u'EDX', 0)
    func_calling = getFunctionBefore(ref.getFromAddress())
    ioctl = getInstructionAt(load_into_edx).getOpObjects(1)[0].getValue()
    print(func_calling.getName() + u': ', hex(ioctl)[:-1])
    func_to_ioctl[func_calling] = hex(ioctl)[:-1]
    func_name_to_ioctl[func_calling.getName()] = hex(ioctl)[:-1]

print(func_to_ioctl)
print(json.dumps(func_name_to_ioctl, indent=4))