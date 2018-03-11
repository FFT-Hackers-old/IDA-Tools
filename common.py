from __future__ import print_function

import os

import ida_bytes
import ida_enum
import ida_nalt
import ida_name
import ida_struct
import ida_ua

import idautils
import idc

from ida_idaapi import BADADDR


# we'll sometimes be passing names to IDA, which expects str, not unicode
def convert_name_str(obj):
    for k, v in obj.items():
        if isinstance(v, unicode):
            obj[k] = v.encode('utf-8')

    return obj


def get_dump_file():
    return os.path.join(idautils.GetIdbDir(), 'dump.json')


class Functions(object):
    KEY = 'functions'

    @staticmethod
    def dump():
        ret = []
        for i, f in enumerate(idautils.Functions()):
            name = ida_name.get_name(f)
            if name.startswith('sub_') or name.startswith('nullsub_'):
                continue

            ret.append({
                'start': f,
                'name': name,
            })
        return ret

    @staticmethod
    def load(infos):
        for info in infos:
            ida_name.set_name(info['start'], info['name'])


class Enums(object):
    KEY = 'enums'

    @staticmethod
    def dump():
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

    @staticmethod
    def load(infos):
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
                ida_enum.add_enum_member(
                    enum_id, member['name'], member['value'])


class Structs(object):
    KEY = 'structs'

    @staticmethod
    def dump():
        ret = []

        for struct_idx, struct_id, struct_name in idautils.Structs():
            struct = ida_struct.get_struc(struct_id)

            members = [{'offset': offset, 'name': name, 'size': size}
                       for offset, name, size in idautils.StructMembers(struct_id)]

            # find all xrefs to any members of this struct
            xrefs = []
            for offset, name, size in idautils.StructMembers(struct_id):
                member = ida_struct.get_member_by_name(struct, name)
                for xref in idautils.XrefsTo(member.id):
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

    @staticmethod
    def load(infos):
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
                    # opinfo_t instance... maybe it should sometimes be
                    # something?
                    None,
                    member['size'],
                )

            # load xrefs to members of the struct
            for xref in info['xrefs']:
                tp = xref['type']

                # offset ref
                if tp == 1:
                    # TODO figure out what second argument does
                    idc.op_plain_offset(xref['from'], 1, xref['offset'])

                # read or write refs
                elif tp == 2 or tp == 3:
                    ida_ua.create_insn(xref['from'], insn)
                    idc.op_stroff(insn, 1, struct.id, 0)

                # TODO
                else:
                    pass


class Arrays(object):
    KEY = 'arrays'

    @staticmethod
    def dump():
        return []

    @staticmethod
    def load(infos):
        for info in infos:
            idc.make_array(info['start'], info['length'])


class Data(object):
    KEY = 'data'

    @staticmethod
    def dump():
        ret = []
        for addr, name in idautils.Names():
            # if any(name.startswith(s) for s in ['byte_', 'word_', 'dword_', 'unk_', 'jpt_']):
            #     continue

            flags = ida_bytes.get_flags(addr)
            if ida_bytes.has_dummy_name(flags) or ida_bytes.has_auto_name(flags) or not ida_bytes.is_data(flags):
                continue

            # print('%08x' % addr, '%08x' % flags, name,
            # ida_bytes.is_data(flags))

            sz = ida_bytes.get_item_size(addr)

            if ida_bytes.is_struct(flags):
                ti = ida_nalt.opinfo_t()
                ida_bytes.get_opinfo(ti, addr, 0, flags)
                # itemsize = ida_bytes.get_data_elsize(addr, flags, ti)
                typ = ida_struct.get_struc_name(ti.tid)
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

    @staticmethod
    def load(infos):
        for info in infos:
            ida_name.set_name(info['address'], info['name'])

            # this code is kind of mashed together... not sure of the right way
            tid = ida_struct.get_struc_id(
                info['type']) if info['type'] else BADADDR
            if info['type']:
                print(info['type'], hex(tid))
                ida_bytes.create_struct(info['address'], info['sz'], tid)
            ida_bytes.create_data(
                info['address'], info['flags'], info['sz'], tid)


items = [Functions, Enums, Structs, Arrays, Data]
