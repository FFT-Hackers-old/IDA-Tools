from __future__ import print_function

import os
import json

import ida_bytes
import ida_enum
import ida_kernwin
import ida_nalt
import ida_name
import ida_offset
import ida_struct
import ida_typeinf
import ida_ua

import idautils
import idc

from ida_idaapi import BADADDR

def filter_none(dict):
	newDict = {}
	for k in dict:
		if dict[k] != None:
			newDict[k] = dict[k]
	return newDict

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

            ret.append(filter_none({
                'start': addr,
                'name': name,
                'type': typ,
            }))
        return ret

    @staticmethod
    def load(infos):
        idc.set_inf_attr(idc.INF_COMPILER, 6)
        for info in infos:
            type = info.get('type', None)
            ida_name.set_name(info['start'], info['name'])
            if type:
                idc.SetType(info['start'], type)

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
                print('[IDA-Sync] Creating new enum %s.' % info['name'])
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
                if member is not None:
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
                print('[IDA-Sync] Creating new struct %s.' % info['name'])
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
            # The 'a' heuristic is fairly bad but we need to filter out IDA's default
            # naming for strings
            if ida_bytes.has_dummy_name(flags) or ida_bytes.has_auto_name(flags) or not ida_bytes.is_data(flags) or name[0] == 'a':
                continue

            # Sometimes the auto-generated names don't actually usually have the
            # right flags set, so skip these auto-looking names.
            if any(name.startswith(s) for s in ['byte_', 'word_', 'dword_', 'unk_', 'jpt_']):
                continue

            sz = ida_bytes.get_item_size(addr)

            if ida_bytes.is_struct(flags):
                ti = ida_nalt.opinfo_t()
                ida_bytes.get_opinfo(ti, addr, 0, flags)
                typ = ida_struct.get_struc_name(ti.tid)
            else:
                typ = None
			
            ret.append(filter_none({
                'address': addr,
                'name': name,
                'type': typ,
                'sz': sz,
                'flags': flags,
            }))

        return ret

    @staticmethod
    def load(infos):
        for info in infos:
            ida_name.set_name(info['address'], info['name'])
            type = info.get('type', None)

            # TODO this code is kind of mashed together... not sure of the
            # right way.
            tid = ida_struct.get_struc_id(type) if type else BADADDR
            if type:
                ida_bytes.create_struct(info['address'], info['sz'], tid)
            ida_bytes.create_data(
                info['address'], info['flags'], info['sz'], tid)


items = [Settings, Enums, Structs, Arrays, Data, Functions]

# We'll sometimes be passing names to IDA, which expects str, not unicode.
def convert_name_str(obj):
    for k, v in obj.items():
        if isinstance(v, unicode):
            obj[k] = v.encode('utf-8')
    return obj

class ImportHandler(ida_kernwin.action_handler_t):
	def activate(self, ctx):
		filename = ida_kernwin.ask_file(False, '*.json', 'Import IDA-Sync JSON file')
		if filename is not None:
			print('[IDA-Sync] Importing %s...' % filename)
			with open(filename) as f:
				j = json.load(f, object_hook=convert_name_str)
			for item in items:
				item.load(j.get(item.KEY, []))
			print('[IDA-Sync] Done')
		return 1

	def update(self, ctx):
		return ida_kernwin.AST_ENABLE_ALWAYS

class ExportHandler(ida_kernwin.action_handler_t):
	def activate(self, ctx):
		filename = ida_kernwin.ask_file(True, '*.json', 'Export IDA-Sync JSON file')
		if filename is not None:
			print('[IDA-Sync] Exporting %s...' % filename)
			j = {item.KEY: item.dump() for item in items}
			with open(filename, 'w') as file:
				json.dump(j, file, indent=2, sort_keys=True, separators=(',', ': '))
			print('[IDA-Sync] Done')
		return 1

	def update(self, ctx):
		return ida_kernwin.AST_ENABLE_ALWAYS

class IDASyncPlugin(ida_idaapi.plugin_t):
	flags = ida_idaapi.PLUGIN_UNL
	comment = "JSON workspaces for IDA"
	help = "Import/export JSON workspaces"
	wanted_name = "IDA-Sync"
	wanted_hotkey = ''

	def init(self):
		import_action = ida_kernwin.action_desc_t(
			'idasync:import',
			'IDA-Sync JSON file...',
			ImportHandler())
		export_action = ida_kernwin.action_desc_t(
			'idasync:export',
			'Create IDA-Sync JSON file...',
			ExportHandler())
		ida_kernwin.register_action(import_action)
		ida_kernwin.register_action(export_action)
		ida_kernwin.attach_action_to_menu(
			'File/Load file/Parse C header file...',
			'idasync:import',
			ida_kernwin.SETMENU_APP
		)
		ida_kernwin.attach_action_to_menu(
			'File/Produce file/Create C header file...',
			'idasync:export',
			ida_kernwin.SETMENU_APP
		)
		print("[IDA-Sync] Loaded")
		return ida_idaapi.PLUGIN_OK

	def run(self, arg):
		pass

	def term(self):
		pass

def PLUGIN_ENTRY():
	return IDASyncPlugin()