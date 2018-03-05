from __future__ import print_function

import json
import os
import time


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

        print(ida_enum.get_enum_name(enum_id), ida_enum.get_enum_flag(enum_id))
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
        members = [{'offset': offset, 'name': name, 'size': size}
                   for offset, name, size in StructMembers(struct_id)]

        print(struct_name)
        mem = ida_struct.get_member(ida_struct.get_struc(struct_id), 0)
        print(ida_struct.get_struct_first_offset())

        ret.append({
            'idx': struct_idx,
            'name': struct_name,
            'members': members,
        })

    return ret


def main():
    fn = os.path.join(os.getcwd(), 'dump.txt')

    j = {
        'functions': get_function_info(),
        'enums': get_enum_info(),
        'structs': get_struct_info(),
    }

    with open(fn,  'w') as out:
        json.dump(j, out, indent=2, sort_keys=True)

    print('Dumped to %s at %s.' % (fn, time.ctime()))


main()
