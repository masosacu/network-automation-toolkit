# -*- coding: utf-8 -*-
import struct
import socket
import exceptions

T2B = {}
T2B["aut"] = 1
T2B["int"] = 3
T2B["ip"] = 3
T2B["str"] = 5
T2B["con"] = 6


B2T = {}
B2T[1] = "aut"
B2T[3] = "int"
B2T[5] = "str"
B2T[6] = "con"

class error(Exception):
  pass

def pack_primitive(key,type,value):
    # L ... size of the entry
    # B ... code of the entry
    # B ... code of the datatype
    # L ... data

    val = value
    s_length = 4
    s_code = 1
    s_dtype = 1
    s_val = 4
    fmt = '>LBBL'

    if type == "int":
        pass
    elif type == 'str'  or type == "aut":
        #make string real string ... cludge for unicode stuff
        s_val = len(str(val))
        fmt = ">LBB%ds" % s_val
        val = str(val)
    elif type == 'ip':
        fmt='>LBB4s'
        val = socket.inet_aton(value)
    else:
        raise error("Protocol pack error","Primitive element expected")

    return struct.pack(fmt, s_length + s_code + s_dtype + s_val , key, T2B[type], val)

def wrap_bytes(key,bytes):
    s_bytes = len(bytes)
    return struct.pack('>LBB%ds' % s_bytes, 6 + s_bytes, key, T2B["con"], bytes)

    
def unpack_primitive(bytes):

    try:
        (length,code,dtype) = struct.unpack(">LBB",bytes[0:6])
    except struct.error,e:
        raise error("Cannot unpack primitive: " + str(e))

    fmt = ">L"
    s_val = 4
    if B2T[dtype] == "int":
        pass
    elif B2T[dtype] == "str"  or B2T[dtype] == "aut":
        s_val = length - 6
        fmt = ">%ds" % s_val
    else:
        raise error("Protocol pack error","Primitive expected")

    return code, dtype, struct.unpack(fmt,bytes[6:length])[0]

def unpack(bytes):

    offset = 0
    ret = []
   
    while True:
        (length,code,dtype) = struct.unpack(">LBB",bytes[offset:offset+6])
        if B2T[dtype] != "con":
            ret.append(unpack_primitive(bytes[offset:offset+length]))
        else:
            ret.append([code,dtype,unpack(bytes[offset+6:offset+length])])
        #print str(ret)

        offset += length
        if offset >= len(bytes):
            break

    return ret

def packet_id(bytes):
    if len(bytes) < 5:
        return 0

    fmt = '>LB'
    return struct.unpack(fmt,bytes[0:5])[1]

def packet_len(bytes):
    if len(bytes) < 4:
        return 0

    fmt = '>L'
    return struct.unpack(fmt,bytes[0:4])[0]