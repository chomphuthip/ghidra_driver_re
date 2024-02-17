#get_ioctl_handler.py
from __future__ import print_function
import json
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.util.datastruct import ListAccumulator
from ghidra.app.services import DataTypeManagerService
#from java.io import File

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

#    config_fh = open('./ghidra_scripts/config.json')
#    config = json.load(config_fh)
#    config_fh.close()
#
#    wdf_structs_path = config['WdfStructs']
#    ntosrknl_path = config['ntosrknl']

dtms = getState().getTool().getService(DataTypeManagerService)
datatypes = {}
datatypes['vbind_dt'] = dtms.getDataType('WdfVersionBind')
datatypes['bind_info_dt'] = dtms.getDataType('WDF_BIND_INFO')
datatypes['wdff_ptr_dt'] = dtms.getDataType('PWDFFUNCTIONS')
datatypes['wdff_dt'] = dtms.getDataType('_WDFFUNCTIONS')
datatypes['config_dt'] = dtms.getDataType('WDF_IO_QUEUE_CONFIG')
datatypes['iocreate_dt'] = dtms.getDataType('IoCreateDevice')
datatypes['driver_object_dt'] = dtms.getDataType('DRIVER_OBJECT')


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
    vbind_dt = datatypes['vbind_dt']
    vbind_func_ptr = creation_symbol.getReferences()[0].getToAddress()
    cmd = ApplyFunctionSignatureCmd(vbind_func_ptr, vbind_dt, SourceType.USER_DEFINED)
    runCommand(cmd)

    #retype 3rd param 
    vbind_ref = getReferencesTo(creation_symbol.getReferences()[0].getFromAddress())[0].getFromAddress()
    load_ins = find_param_load_by_ins(vbind_ref, u'LEA', u'R8', 0)
    if load_ins == None:
        print('unable to get bindinfo')
        exit()
    bind_info = toAddr(getInstructionAt(load_ins).getOpObjects(1)[0].getValue())
    bind_info_dt = datatypes['bind_info_dt']
    removeDataAt(bind_info)
    bind_info_data = createData(bind_info, bind_info_dt)

    #retype FuncTable to WDFFUNCTIONS*
    wdff_ptr_dt = datatypes['wdff_ptr_dt']
    wdff_ptr = bind_info_data.getComponent(4).getValue()
    removeDataAt(wdff_ptr)
    createData(wdff_ptr, wdff_ptr_dt)

    #get IoQueueCreateCall 
    io_queue_create_refs = ListAccumulator()
    wdff_dt = datatypes['wdff_dt']
    ReferenceUtils.findDataTypeReferences(
        io_queue_create_refs,
        getDataTypes('_WDFFUNCTIONS')[0],
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

    config_dt = datatypes['config_dt']
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

#WDM
#apply function sig to IoCreateDevice
#retype first parameter as DRIVER_OBJECT
#get DRIVER_OBJECT->MajorFunction[0xe] and bookmark

if wdf_or_wdm == 'wdm':

    #apply function sig to IoCreateDevice
    iocreate_dt = datatypes['iocreate_dt']
    iocreate_func_ptr = creation_symbol.getReferences()[0].getToAddress()
    cmd = ApplyFunctionSignatureCmd(iocreate_func_ptr, iocreate_dt, SourceType.USER_DEFINED)
    runCommand(cmd)

    #retype first parameter as DRIVER_OBJECT
    iocreate_ref = getReferencesTo(creation_symbol.getReferences()[0].getFromAddress())[0].getFromAddress()
    driver_object_dt = datatypes['driver_object_dt']
    iocreate_caller = getFunctionBefore(iocreate_ref)
    driver_object_var = iocreate_caller.getParameters()[0]
    driver_object_var.setDataType(driver_object_dt, True, True, SourceType.USER_DEFINED)

    #get DRIVER_OBJECT->MajorFunction[0xe] and bookmark
    mj_refs = ListAccumulator()
    ReferenceUtils.findDataTypeReferences(
        mj_refs,
        getDataTypes('DRIVER_OBJECT')[0],
        u'MajorFunction',
        currentProgram,
        ghidra.util.task.TaskMonitor.DUMMY
    )
    for mj_ref in mj_refs:
        if u'MajorFunction[0xe] = ' in mj_ref.context.getPlainText():
            #get address of reference
            ref_addr = mj_ref.locationOfUse

            #get register that holds IRP_MJ_DEVICE_CONTROL
            dev_ctrl_fn_ptr_reg = getInstructionAt(ref_addr).getDefaultOperandRepresentation(1)

            #find_param_load_by_ins the instruction that loaded it into that reg
            reg_load_addr = find_param_load_by_ins(ref_addr, u'LEA', dev_ctrl_fn_ptr_reg, 0)
            dev_ctrl_fn_addr = toAddr(getInstructionAt(reg_load_addr).getOpObjects(1)[0].getValue())

            #bookmark that address
            createBookmark(
                dev_ctrl_fn_addr,
                'Driver Info',
                'IRP_MJ_DEVICE_CONTROL'
            )
