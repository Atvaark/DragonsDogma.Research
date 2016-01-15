#---------------------------------------------------------------------
# Rename type factories
#
# * Adds labels to the type factory vtable locations.
# * Adds labels to vtables when using inline constructors
# * Doesn't work with constructors that the code calls or jumps to
#---------------------------------------------------------------------
from idautils import *

def handleInlineConstructor(ea,name):
	#print "%X" % R4
	E = list(FuncItems(ea))
	hit = -1
	reg = ["eax"]
	opnd = ["dword ptr [eax]"]
	movRegCount = 0
	movCount = 0
	callCount = 0
	for e in E:	
		# start logging after the 2nd call.
		if callCount < 2:
			if GetMnem(e) == "call":
				callCount += 1
			continue		
					
		if GetMnem(e) == "mov" and GetOpType(e,0) == 3 and GetOpType(e,1) == 5 and GetOpnd(e,0) in opnd:
			hit = e
			movCount += 1
			#print "%X : %s %s %s %s %s %s" % (e,GetOpType(e,0),GetOpType(e,1),GetOpnd(e,0),GetOpnd(e,1),GetOperandValue(e,0), GetOperandValue(e,1))
		elif GetMnem(e) == "mov" and GetOpType(e,0) == 1 and GetOpType(e,1) == 1 and GetOpnd(e,1) in reg:
			newReg = GetOpnd(e,0)
			#print "%s -> %s" % (reg, newReg)		
			reg.append(newReg)
			opnd.append("dword ptr [%s]" % newReg)
			movRegCount += 1
			#print "%X : %s %s %s %s %s %s" % (e,GetOpType(e,0),GetOpType(e,1),GetOpnd(e,0),GetOpnd(e,1),GetOperandValue(e,0), GetOperandValue(e,1))
			
	if hit == -1:
		print "%X miss %i %i %s" % (ea, movCount, movRegCount, opnd)			
	else:
		hitVtable = GetOperandValue(hit, 1)
		idc.MakeName(hitVtable, "%s_vtable_0" % name)		
		print "%X hit %i %X %s %X" % (ea, movCount, hit, GetDisasm(hit), hitVtable)

def main():
	tracedfunc = idc.FindBinary(0, 1, "8B 44 24 04 56 8B F1 8B 56 18 8B 4C 24 10 81 E1 ?? ?? ?? ?? 81 E2 ?? ?? ?? ??")

	if tracedfunc == idaapi.BADADDR:
		print "register_type_factory function not found"
		return
	
	#print "found at %X" % tracedfunc
	for ref in CodeRefsTo(tracedfunc, 1):
		#print "  called from %s(0x%x)" % (GetFunctionName(ref), ref)

		E = list(FuncItems(ref))
		
		count = 0
		for e in E:
			count = count + 1
			
			if GetMnem(e) == "push" and count == 1:
				A7 = GetOpnd(e, 0)
			elif GetMnem(e) == "push" and count == 2:
				A6 = GetOpnd(e, 0)
			elif GetMnem(e) == "push" and count == 3:
				A5 = GetOperandValue(e, 0)
			elif GetMnem(e) == "push" and count == 4:
				A4 = GetOperandValue(e, 0)
			elif GetMnem(e) == "push" and count == 5:
				A3 = GetOperandValue(e, 0)
			elif GetMnem(e) == "push" and count == 6:
				A2 = GetString(GetOperandValue(e, 0), -1, ASCSTR_C)
			elif GetMnem(e) == "mov" and count == 7:
				A1 = GetOperandValue(e, 1)
			elif GetMnem(e) == "push" and count == 9:
				R1 = GetOperandValue(e, 0)
			elif GetMnem(e) == "mov" and count == 10:
				R2 = GetOperandValue(e, 1)
		
		print "%s\t%s\t\"%s\"\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (hex(ref), hex(A1), A2, hex(A3), A4, A5, A7, A7, hex(R1), hex(R2))
		
		# A1 = p_factory
		# A2 = Name
		# A3 = p_allocator
		# A4 = TypeId
		# A5 = Size
		# A6 = ?
		# A7 = ?
		name = A2.replace("<","_").replace(">","_").replace(" ", "")		
		idc.MakeName(A1, "p_%s_factory" % name)
		idc.MakeName(R2, "%s_factory" % name)
		
		R3 = NextHead(R2, -1)
		if R3 == idaapi.BADADDR:
			#print "error: create function not found"
			continue			
		R4 = Dword(R3)	
		
		if not idaapi.get_func(R4):		
			#print "error: not a function %X" % R4
			continue		
		idc.MakeName(R4, "create_%s" % name)		
		handleInlineConstructor(R4,name)	
if __name__ == "__main__":
  main()