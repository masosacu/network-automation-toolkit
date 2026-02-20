# -*- coding: utf-8 -*-
__vis_filter = """................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""

def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []
    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % ord(x) for x in line])
        line = line.translate(__vis_filter)
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)

def make_dict(lst):
    ret = {}
    ret["others"] = []
    for item in lst:
        if len(item) == 3:
            name = item[0]
            type = item[1]
            value= item[2]
            if name not in ret.keys():
                ret[name] = []

            entry = {}
            entry['type']=type
            if type == 0x6:
                entry['value'] = make_dict(value)
            else:
                entry['value']=value
            ret[name].append(entry)

        else:
            ret["others"].append(item)

    return ret