def xorMes(mes,xorValue):
    n = len(xorValue)
    result = b''
    for i in range(len(mes)):
        result+= (mes[i]^(xorValue[i%8])).to_bytes(1)
    return result

def decimalToBit(decimal,numbyte):
    numbit = numbyte*8
    
    return ('{0:0'+str(numbit)+'b}').format(decimal)

def bitstring_to_bytes(s,numbyte):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    result= bytes(b[::-1])
    if len(result) != numbyte:
        result = b'\x00' *(numbyte - len(result))+result
    return result

def intToByte(num,numbyte):
    return num.to_bytes(numbyte, byteorder ='big')
