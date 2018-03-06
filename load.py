from __future__ import print_function

import json
import time


def load_functions(infos):
    for info in infos:
        ida_name.set_name(info['start'], info['name'])


def load_enums(infos):
    for info in infos:
        enum_id = ida_enum.get_enum(info['name'])
        if enum_id == BADADDR:
            print('Creating new enum %s.' % info['name'])
            enum_id = ida_enum.add_enum(
                info['idx'],
                info['name'],
                info['flag'],
            )
        else:
            ida_enum.set_enum_idx(enum_id, info['idx'])
            ida_enum.set_enum_flag(enum_id, info['flag'])

        ida_enum.set_enum_width(enum_id, info['width'])

        for member in info['members']:
            ida_enum.add_enum_member(enum_id, member['name'], member['value'])


def load_structs(infos):
    insn = ida_ua.insn_t()

    for info in infos:
        # Find or create struct.
        struct_id = ida_struct.get_struc_id(info['name'])
        if struct_id == BADADDR:
            print('Creating new struct %s.' % info['name'])
            struct_id = ida_struct.add_struc(info['idx'], info['name'])
        struct = ida_struct.get_struc(struct_id)

        ida_struct.set_struc_idx(struct, info['idx'])

        for member in info['members']:
            ida_struct.add_struc_member(
                struct,
                member['name'],
                member['offset'],
                # flag
                0,
                # opinfo_t instance... maybe it should sometimes be something?
                None,
                member['size'],
            )

        # load xrefs to members of the struct
        for xref in info['xrefs']:
            tp = xref['type']

            # offset ref
            if tp == 1:
                # TODO figure out what second argument does
                op_plain_offset(xref['from'], 1, xref['offset'])

            # read or write refs
            elif tp == 2 or tp == 3:
                ida_ua.create_insn(xref['from'], insn)
                idc.op_stroff(insn, 1, struct.id, 0)

            # TODO
            else:
                pass


def load_arrays(infos):
    for info in infos:
        idc.make_array(info['start'], info['length'])


def load_data(infos):
    for info in infos:
        ida_name.set_name(info['address'], info['name'])

        # this code is kind of mashed together... not sure of the right way
        tid = get_struc_id(info['type']) if info['type'] else BADADDR
        if info['type']:
            print(info['type'], hex(tid))
            ida_bytes.create_struct(info['address'], info['sz'], tid)
        ida_bytes.create_data(info['address'], info['flags'], info['sz'], tid)


# we'll sometimes be passing names to IDA, which expects str, not unicode


def convert_name_str(obj):
    for k, v in obj.items():
        if isinstance(v, unicode):
            obj[k] = v.encode('utf-8')

    return obj


def main():
    fn = os.path.join(os.getcwd(), 'dump.json')

    with open(fn) as f:
        j = json.load(f, object_hook=convert_name_str)

    load_functions(j['functions'])
    load_enums(j['enums'])
    load_structs(j['structs'])
    load_data(j['data'])

    print('Finished load from %s at %s.' % (fn, time.ctime()))


main()
