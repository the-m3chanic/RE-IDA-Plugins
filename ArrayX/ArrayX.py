import idaapi 
import idc 
import ida_kernwin

class ArrayX(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Array exporting made easy"
    help = "Allows for convenient exporting of arrays of various sizes"
    wanted_name = "ArrayX"
    wanted_hotkey = "Ctrl-Shift-E"
    EXPORT_FILE = "array_export.txt"
    EXPORT_TO_FILE = True


    def isValidHexAddr(addr: str) -> bool:
        """ Validates if the given address is a valid hex address """

        try: 
            flag1 = addr.startswith("0x")
        except AttributeError:
            flag1 = False
        
        try:
            flag2 = int(addr, 16)
        except (ValueError, TypeError):
            flag2 = 0
        
        return (flag1 and flag2)

    def convertToHexInt(self, addr: str) -> int:
        """ Converts a hex string to an integer """

        if not ArrayX.isValidHexAddr(addr):
            ida_kernwin.warning(
                "Not a valid hex address!"
            )
            ArrayX.term(self)
        else:
            return int(addr, 16)


    def getArrayAddress():
        """ Prompts the user for the base address of the array """

        baseAddr = ida_kernwin.ask_str(
            "0x0",
            0,
            "Enter the base address of the array you want to export",
        )

        idaapi.msg(f"Base address: {baseAddr}\n")
        baseAddr = ArrayX.convertToHexInt(baseAddr)
        return baseAddr
        
        
    def getArrayType(self):
        """ Prompts the user for the type of the array """

        arrayTypes = ["byte", "word", "dword", "qword", "string", "wideString"]
        arrayType = ida_kernwin.ask_str(
            "Byte",
            0,
            "Enter the type of the array you want to export\n[Byte, Word, Dword, Qword, String, wideString]",
        )

        try: 
            arrayType = arrayType.lower()
        except AttributeError:
            ida_kernwin.warning(
                "Not a valid array type!"
            )
            ArrayX.term(self)
        
        if arrayType not in arrayTypes:
            ida_kernwin.warning(
                "Not a valid array type!"
            )
            ArrayX.term(self)
        

        return arrayType.lower() 

    def getArraySize(self):
        """ Prompts the user for the size of the array """

        arraySize = ida_kernwin.ask_str(
            "0",
            0,
            "Enter the size of the array you want to export",
        )

        try:
            arraySize = int(arraySize)
        except ValueError:
            ida_kernwin.warning(
                "Not a valid array size!"
            )
            ArrayX.term(self)

        return arraySize


    def exportByteArr(baseAddr: int, arraySize: int) -> list:
        """ Exports a byte array """

        array = []
        addr = baseAddr

        for i in range(arraySize):
            x = (idaapi.get_bytes(addr, 1))
            addr += 1
            x = int.from_bytes(x, byteorder="little")
            array.append(x)
        
        return array
    
    def exportWordArr(baseAddr: int, arraySize: int) -> list:
        """ Exports a word array """

        array = []
        addr = baseAddr

        for i in range(arraySize):
            x = (idaapi.get_bytes(addr, 2))
            addr += 2
            x = int.from_bytes(x, byteorder="little")
            array.append(x)
        
        return array

    def exportDwordArr(baseAddr: int, arraySize: int) -> list:
        """ Exports a dword array """

        array = []
        addr = baseAddr

        idaapi.msg(f"address type: {type(addr)}")
        for i in range(arraySize):
            x = (idaapi.get_bytes(addr, 4))
            addr += 4
            x = int.from_bytes(x, byteorder="little")
            array.append(x)
        
        return array
    
    def exportQwordArr(baseAddr: int, arraySize: int) -> list:
        """ Exports a qword array """

        array = []
        addr = baseAddr

        for i in range(arraySize):
            x = (idaapi.get_bytes(addr, 8))
            addr += 8
            x = int.from_bytes(x, byteorder="little")
            array.append(x)
        
        return array
    
    def exportStringArr(baseAddr: int, arraySize: int) -> list:
        """ Exports a string array """

        array = []
        addr = baseAddr

        for i in range(arraySize):
            x = (idaapi.get_bytes(addr, 1))
            addr += 1
            x = int.from_bytes(x, byteorder="little")
            array.append(chr(x))
        
        return array
    
    def exportWideString(baseAddr: int, arrayType: str, arraySize: int) -> list:
        """ Exports a Wide String (as seen on Windows) """

        array = []
        addr = baseAddr 

        for i in range(arraySize):
            x = (idaapi.get_bytes(addr, 1))
            addr += 2
            x = int.from_bytes(x, byteorder="little")
            array.append(chr(x))

        return array
        
    def exportArray(baseAddr: int, arrayType: str, arraySize: int) -> list:
        """ Bottleneck function to export the array """

        array = []
        if arrayType == "byte":
            array = ArrayX.exportByteArr(baseAddr, arraySize)
        elif arrayType == "word":
            array = ArrayX.exportWordArr(baseAddr, arraySize)
        elif arrayType == "dword":
            array = ArrayX.exportDwordArr(baseAddr, arraySize)
        elif arrayType == "qword":
            array = ArrayX.exportQwordArr(baseAddr, arraySize)
        elif arrayType == "string":
            array = ArrayX.exportStringArr(baseAddr, arraySize)
        elif arrayType == "wideString":
            array = ArrayX.exportWideString(baseAddr, arraySize)

        return array
    


    def init(self):
        idaapi.msg("ArrayX initialised. Ctrl-Shift-E to export data\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("ArrayX is running...\n")
        baseAddr = ArrayX.getArrayAddress()
        arrayType = ArrayX.getArrayType()
        arraySize = ArrayX.getArraySize()
        
        idaapi.msg(f"Exporting -- Base address: {hex(baseAddr)}, Array type: {arrayType}, Array size: {arraySize}\n")
        
        array = ArrayX.exportArray(baseAddr, arrayType, arraySize)
        idaapi.msg(f"Array: {array}\n")

        if ArrayX.EXPORT_TO_FILE:
            fileName = ida_kernwin.ask_str(
            "Byte",
            0,
            "Enter the name of the file you would like to export the results to: ",
            )
            with open(fileName, "w") as f:
                f.write(f"Base address: {baseAddr}\n")
                f.write(f"Array type: {arrayType}\n")
                f.write(f"Array size: {arraySize}\n")
                f.write(f"Array: {array}\n")
        else: 
            idaapi.msg(f"No request for file write made, exiting normally...")


    def term(self):
        idaapi.msg("ArrayX terminated\n")

def PLUGIN_ENTRY():
    return ArrayX()
