#propagate.py
#when your cursor is on a function call, propagate the varible names
#i binded it to ctrl shift p

from __future__ import print_function
from ghidra.app.decompiler import ClangToken
from ghidra.program.model.symbol import SourceType


#get variable names from particular function call
#get the line text
#parse to see which variables are in which parameter

#get HighFunction
#get Function from HighFunction
#get Parameters
#Parameter1.setName(u'bob')

token = currentLocation.getToken()
if token.getSyntaxType() != ClangToken.FUNCTION_COLOR:
    print('Put your cursor on a function call.')
    exit()

pcode_op = token.getPcodeOp()

call_params = []
unamed_params = 0

for pcode_input in pcode_op.getInputs()[1:]:
    #each input is a varnode
    name = pcode_input.getHigh().getName()

    if pcode_input.isConstant():
        name = u'CONST_' + unicode(hex(pcode_input.getOffset())[:-1])

    if name == u'UNNAMED':
        name = name + u'_' + unicode(unamed_params)
        unamed_params = unamed_params + 1
    call_params.append(name)

print(call_params)

func = getFunctionAt(token.getPcodeOp().getInput(0).getAddress())
for func_param, call_param in zip(func.getParameters(), call_params):
    func_param.setName(call_param, SourceType.USER_DEFINED)