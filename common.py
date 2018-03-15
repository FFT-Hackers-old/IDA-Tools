from __future__ import print_function

import os

import ida_bytes
import ida_enum
import ida_nalt
import ida_name
import ida_offset
import ida_struct
import ida_typeinf
import ida_ua

import idautils
import idc

from ida_idaapi import BADADDR


def get_dump_file():
    return os.path.join(idautils.GetIdbDir(), 'dump.json')


class Settings(object):

    """Handles miscellaneous global settings."""

    KEY = 'settings'

    @staticmethod
    def dump():
        return {
            'compiler': idc.get_inf_attr(idc.INF_COMPILER).id,
        }

    @staticmethod
    def load(info):
        idc.set_inf_attr(idc.INF_COMPILER, info['compiler'])


class Functions(object):

    """Handles names given to subroutines."""

    KEY = 'functions'

    @staticmethod
    def dump():
        ret = []
        for addr in idautils.Functions():
            name = ida_name.get_name(addr)
            if name.startswith('sub_') or name.startswith('nullsub_'):
                continue

            # For some reason, this get_type function doesn't include the name,
            # but the SetType function expects it.
            typ = ida_typeinf.idc_get_type(addr)
            if typ:
                typ = typ.replace('__cdecl', '__cdecl %s' % name) + ';'

            ret.append({
                'start': addr,
                'name': name,
                'type': typ,
            })
        return ret

    @staticmethod
    def load(infos):
        idc.set_inf_attr(idc.INF_COMPILER, 6)
        for info in infos:
            ida_name.set_name(info['start'], info['name'])
            if info['type']:
                idc.SetType(info['start'], info['type'])


class Enums(object):

    """Handles enum definitions."""

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

    """Handles struct definitions and uses of members as offsets to memory accesses."""

    KEY = 'structs'

    @staticmethod
    def dump():
        ret = []

        for struct_idx, struct_id, struct_name in idautils.Structs():
            struct = ida_struct.get_struc(struct_id)

            members = [{'offset': offset, 'name': name, 'size': size}
                       for offset, name, size in idautils.StructMembers(struct_id)]

            # Find all xrefs to any members of this struct.
            xrefs = []
            for offset, name, size in idautils.StructMembers(struct_id):
                member = ida_struct.get_member_by_name(struct, name)
                for xref in idautils.XrefsTo(member.id):
                    d = {
                        'from': xref.frm,
                        'type': xref.type,
                    }

                    # Get offset base if it's an offset xref.
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

            # Create struct members.
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

            # Create xrefs to members of the struct as offsets.
            for xref in info['xrefs']:
                typ = xref['type']

                # Offset xref.
                if typ == 1:
                    # TODO figure out what second argument does.
                    idc.op_plain_offset(xref['from'], 1, xref['offset'])

                # Read/write xrefs.
                elif typ in [2, 3]:
                    ida_ua.create_insn(xref['from'], insn)
                    idc.op_stroff(insn, 1, struct.id, 0)

                # TODO do the other cases come up?
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

    """Handles struct/array definitions and labels in memory."""

    KEY = 'data'

    @staticmethod
    def dump():
        ret = []
        for addr, name in idautils.Names():
            flags = ida_bytes.get_flags(addr)
            if ida_bytes.has_dummy_name(flags) or ida_bytes.has_auto_name(flags) or not ida_bytes.is_data(flags):
                print('skip auto:', name)
                continue

            # Sometimes the auto-generated names don't actually usually have the
            # right flags set, so skip these auto-looking names.
            if any(name.startswith(s) for s in ['byte_', 'word_', 'dword_', 'unk_', 'jpt_']):
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

            # TODO this code is kind of mashed together... not sure of the
            # right way.
            tid = ida_struct.get_struc_id(
                info['type']) if info['type'] else BADADDR
            if info['type']:
                print(info['type'], hex(tid))
                ida_bytes.create_struct(info['address'], info['sz'], tid)
            ida_bytes.create_data(
                info['address'], info['flags'], info['sz'], tid)


items = [Settings, Enums, Structs, Arrays, Data, Functions]
