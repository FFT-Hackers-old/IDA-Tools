from __future__ import print_function

import json
import os
import time


def list_attrs(x):
    # for k, v in x.__dict__.items():
    for k in dir(x):
        v = getattr(x, k)
        if isinstance(v, (int, long)) and v >= 10000:
            v = hex(v)
        print('-', k, v)


def get_function_info():
    ret = []
    for i, f in enumerate(Functions()):
        if Name(f).startswith('sub_') or Name(f).startswith('nullsub_'):
            continue

        ret.append({
            'start': f,
            'name': Name(f),
        })
    return ret


def get_enum_info():
    ret = []
    for i in range(ida_enum.get_enum_qty()):
        enum_id = ida_enum.getn_enum(i)

        members = []

        class V(ida_enum.enum_member_visitor_t):

            def visit_enum_member(self, cid, value):
                members.append({
                    'value': value,
                    'name': ida_enum.get_enum_member_name(cid),
                })
                return 0

        ida_enum.for_all_enum_members(enum_id, V())

        ret.append({
            'idx': ida_enum.get_enum_idx(enum_id),
            'name': ida_enum.get_enum_name(enum_id),
            'width': ida_enum.get_enum_width(enum_id),
            'flag': ida_enum.get_enum_flag(enum_id),
            'members': members,
        })

    return ret


def get_struct_info():
    ret = []

    for struct_idx, struct_id, struct_name in Structs():
        struct = ida_struct.get_struc(struct_id)

        members = [{'offset': offset, 'name': name, 'size': size}
                   for offset, name, size in StructMembers(struct_id)]

        # find all xrefs to any members of this struct
        xrefs = []
        for offset, name, size in StructMembers(struct_id):
            member = ida_struct.get_member_by_name(struct, name)
            for xref in XrefsTo(member.id):
                # if xref.frm in (0x88a8324, 0x8887c28):
                #     print('-', xref.frm)
                #     for k, v in xref.__dict__.items():
                #         print(k, v)

                d = {
                    'from': xref.frm,
                    'type': xref.type,
                }

                # offset type
                if xref.type == 1:
                    d['offset'] = ida_offset.get_offbase(xref.frm, 1)

                xrefs.append(d)

        ret.append({
            'idx': struct_idx,
            'name': struct_name,
            'members': members,
            'xrefs': xrefs,
        })

    return ret


def get_data_info():
    ret = []
    for addr, name in Names():
        # if any(name.startswith(s) for s in ['byte_', 'word_', 'dword_', 'unk_', 'jpt_']):
        #     continue

        flags = ida_bytes.get_flags(addr)
        if ida_bytes.has_dummy_name(flags) or ida_bytes.has_auto_name(flags) or not ida_bytes.is_data(flags):
            continue

        # print('%08x' % addr, '%08x' % flags, name, ida_bytes.is_data(flags))

        sz = ida_bytes.get_item_size(addr)

        if ida_bytes.is_struct(flags):
            ti = ida_nalt.opinfo_t()
            ida_bytes.get_opinfo(ti, addr, 0, flags)
            # itemsize = ida_bytes.get_data_elsize(addr, flags, ti)
            typ = get_struc_name(ti.tid)
        else:
            # itemsize = ida_bytes.get_item_size(addr)
            typ = None

        ret.append({
            'address': addr,
            'name': name,
            'type': typ,
            'sz': sz,
            'flags': flags,
        })

    return ret


def main():
    fn = os.path.join(os.getcwd(), 'dump.json')

    j = {
        'functions': get_function_info(),
        'enums': get_enum_info(),
        'structs': get_struct_info(),
        'data': get_data_info(),
    }

    with open(fn,  'w') as out:
        json.dump(j, out, indent=2, sort_keys=True, separators=(',', ': '))

    print('Dumped to %s at %s.' % (fn, time.ctime()))


main()
