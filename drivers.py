#drivers.py
from __future__ import print_function
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.util.datastruct import ListAccumulator

#get imports
#if WdfVersionBind, its WDF
#if IoCreateDevice, its WDM

#WDF
#apply function sig to WdfVersionBind
#find all references to pfnIoQueueCreate
#retype third param to be WDF_IO_QUEUE_CONFIG 
#if there is an EvtIoDeviceControl, get it and bookmark

#WDM
#apply function sig to IoCreateDevice
#retype first parameter as DRIVER_OBJECT
#get DRIVER_OBJECT->MajorFunction[0xe] and bookmark


def find_param_load_by_ins(addr, mnem, op, op_index, back = 0):
    ins = getInstructionAt(addr)
    print('find_param_load_by_ins: ', ins)
    if ins.getDefaultOperandRepresentation(op_index) == op and ins.getMnemonicString() == mnem:
        return addr
    else:
        back = back + 1
        if back == 20:
            return None
        return find_param_load_by_ins(getInstructionBefore(addr).getAddress(), mnem, op, op_index, back)

def get_rsp(target_addr, current_addr = None, rsp = 0):
    if current_addr == None:
        current_addr = getFunctionBefore(target_addr).getEntryPoint()
    if target_addr == current_addr:
        return rsp
    ins = getInstructionAt(current_addr)
    print('get_rsp: ', ins)
    if ins.getMnemonicString() == u'PUSH':
        rsp = rsp - 8
    elif ins.getMnemonicString() == u'POP':
        rsp = rsp + 8
    elif ins.getDefaultOperandRepresentation(0) == u'RSP':
        if ins.getMnemonicString() == u'SUB':
            rsp = rsp - int(ins.getDefaultOperandRepresentation(1), 16)
    return get_rsp(target_addr, getInstructionAfter(current_addr).getAddress(), rsp)


symbol_table = currentProgram.getSymbolTable()

#returns an iterrator that points to the next symbol
imported_symbols = symbol_table.getExternalSymbols()

wdf_or_wdm = False
creation_symbol = False
for imported_symbol in imported_symbols:
    if imported_symbol.getName() == u'WdfVersionBind':
        creation_symbol = imported_symbol
        wdf_or_wdm = 'wdf'
    if imported_symbol.getName() == u'IoCreateDevice':
        creation_symbol = imported_symbol
        wdf_or_wdm = 'wdm'

if wdf_or_wdm == False:
    print('couldn\'t get decide if WDM or WDF')
    exit()

#WDF
#apply function sig to WdfVersionBind
#retype 3rd param to WDF_BIND_INFO
#retype FuncTable to WDFFUNCTIONS*
#find all references to pfnIoQueueCreate
#retype third param to be WDF_IO_QUEUE_CONFIG 
#if there is an EvtIoDeviceControl, get it and bookmark

if wdf_or_wdm == 'wdf':

    #apply function sig to WdfVersionBind
    vbind_dt = getDataTypes('WdfVersionBind')[0]
    vbind_func_ptr = creation_symbol.getReferences()[0].getToAddress()
    cmd = ApplyFunctionSignatureCmd(vbind_func_ptr, vbind_dt, SourceType.USER_DEFINED)
    runCommand(cmd)

    #retype 3rd param 
    vbind_func_ptr = creation_symbol.getReferences()[0].getToAddress()
    vbind_ref = getReferencesTo(creation_symbol.getReferences()[0].getFromAddress())[0].getFromAddress()
    load_ins = find_param_load_by_ins(vbind_ref, u'LEA', u'R8', 0)
    if load_ins == None:
        print('unable to get bindinfo')
        exit()
    bind_info = toAddr(getInstructionAt(load_ins).getOpObjects(1)[0].getValue())
    bind_info_dt = getDataTypes('WDF_BIND_INFO')[0]
    removeDataAt(bind_info)
    bind_info_data = createData(bind_info, bind_info_dt)

    #retype FuncTable to WDFFUNCTIONS*
    wdff_ptr_dt = getDataTypes('WDFFUNCTIONS *')[0]
    wdff_ptr = bind_info_data.getComponent(4).getValue()
    removeDataAt(wdff_ptr)
    createData(wdff_ptr, wdff_ptr_dt)

    #get IoQueueCreateCall 
    io_queue_create_refs = ListAccumulator()
    wdff_dt = getDataTypes('_WDFFUNCTIONS')[0]
    ReferenceUtils.findDataTypeReferences(
        io_queue_create_refs,
        wdff_dt,
        u'pfnWdfIoQueueCreate',
        currentProgram,
        ghidra.util.task.TaskMonitor.DUMMY
    )
    if io_queue_create_refs.get() == []:
        print('WdfIoQueueCreate not called')
        exit()
    for ref in io_queue_create_refs.get():
        createBookmark(
           ref.locationOfUse,
           u'Driver Info',
           u'IoQueueCreate'
        )

    #retype third param to be WDF_IO_QUEUE_CONFIG 
    io_queue_create_ref = io_queue_create_refs.get()[0].locationOfUse
    caller = getFunctionBefore(io_queue_create_ref)
    caller_stack_frame = caller.getStackFrame()
    caller_rsp = get_rsp(io_queue_create_ref)
    print(caller_rsp)
    config_load_ins = find_param_load_by_ins(io_queue_create_ref, u'LEA', u'R8', 0)
    if config_load_ins == None:
        print('unable to find queue_config')
        exit()
    config_load_rsp_offset = getInstructionAt(config_load_ins).getOpObjects(1)[1]
    config_offset = config_load_rsp_offset.getValue() + caller_rsp


    config_dt = getDataTypes('WDF_IO_QUEUE_CONFIG')[0]
    caller_stack_frame.clearVariable(config_offset)
    config_var = caller_stack_frame.createVariable(u'queue_config', config_offset, config_dt, ghidra.program.model.symbol.SourceType.USER_DEFINED)

    #if there is an EvtIoDeviceControl (config+0x28), get it and bookmark

    #get the offset where EvtIoDeviceControl field is
    evt_io_dev_ctrl_rsp_offset = int(config_load_rsp_offset.getValue() + 0x28)
    print('queue_config.EvtIoDeviceControl relative to RSP:', evt_io_dev_ctrl_rsp_offset)

    #get the register that holds the pointer before it is loaded into that offset
    print(u'qword ptr [RSP + ' + hex(evt_io_dev_ctrl_rsp_offset) + ']')
    load_func_ptr_offset_addr = find_param_load_by_ins(io_queue_create_ref, u'MOV', u'qword ptr [RSP + ' + hex(evt_io_dev_ctrl_rsp_offset) + ']', 0)
    reg_with_ptr = getInstructionAt(load_func_ptr_offset_addr).getDefaultOperandRepresentation(1)

    #find_param_loaded_ins on whatever register is used to fill that field
    load_func_ptr_reg_addr = find_param_load_by_ins(load_func_ptr_offset_addr, u'LEA', reg_with_ptr, 0)

    #bookmark lea'd pointer
    evt_io_dev_ctrl_addr = toAddr(getInstructionAt(load_func_ptr_reg_addr).getOpObjects(1)[0].getValue())
    createBookmark(
        evt_io_dev_ctrl_addr,
        u'Driver Info',
        u'EvtIoDeviceControl'
    )