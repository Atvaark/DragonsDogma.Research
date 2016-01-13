#---------------------------------------------------------------------
# Rename type factories
#
# Adds labels to the type factory vtable locations.
#
#---------------------------------------------------------------------
from idautils import *

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
		Name = A2.replace("<","_").replace(">","_").replace(" ", "")		
		idc.MakeName(A1, "p_%s_factory" % Name)
		idc.MakeName(R2, "%s_factory" % Name)

if __name__ == "__main__":
  main()