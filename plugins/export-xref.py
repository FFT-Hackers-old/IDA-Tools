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

class export_handler_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        addr = ida_kernwin.askaddr(0, "Target address")
        if addr == BADADDR:
            print('[Export-Xref] Bad address given')
            return 1
        filename = ida_kernwin.ask_file(True, '*', 'Export Xrefs to...')
        if filename is None:
            return 1
        print('[Export-Xref] Exporting %s...' % filename)
        with open(filename, 'w') as f:
            for x in XrefsTo(addr, 0):
                print("0x%08x," % x.frm, file=f)
        print('[Export-Xref] Done')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class export_xref_t(ida_idaapi.plugin_t):
    flags = 0
    comment = "Export Xref into a C-friendly format"
    help = "Export Xref"
    wanted_name = "Export-Xref"
    wanted_hotkey = ''

    def init(self):
        export_action = ida_kernwin.action_desc_t(
            'export-xref:export',
            'Export Xref...',
            export_handler_t())
        ida_kernwin.register_action(export_action)
        ida_kernwin.attach_action_to_menu(
            'File/Produce file/',
            'export-xref:export',
            ida_kernwin.SETMENU_APP
        )
        print("[Export-Xref] Loaded")
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return export_xref_t()