#!/usr/bin/env python3
# $Id$
# Copyright (C) 2005,2008 Igor Belyi <belyi@users.sourceforge.net>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import gtk, gobject, gtk.glade
import gettext
import time, sys, os
from pyme import errors, core
from pyme.core import Context, Data, pubkey_algo_name
from pyme.constants import validity, status, keylist, sig, sigsum

# Enable internationalization using gpa translation pages.
gettext.install('gpa', None, 1)
gtk.glade.bindtextdomain('gpa')
gtk.glade.textdomain('gpa')

# Thanks to Bernhard Reiter for pointing out the following:
# gpgme_check_version() necessary for initialisation according to 
# gpgme 1.1.6 and this is not done automatically in pyme-0.7.0
print("gpgme version:", core.check_version())

# Helper functions to convert non-string data into printable strings
def sec2str(secs, empty="_(Unknown)"):
    "Convert seconds since 1970 into mm/dd/yy string"
    if secs > 0:    return time.strftime("%m/%d/%y", time.localtime(secs))
    elif secs == 0: return empty
    else:           return ""

trusts = {
    validity.UNDEFINED: "Unknown",
    validity.NEVER: "Never",
    validity.MARGINAL: "Marginal",
    validity.FULL: "Full",
    validity.ULTIMATE: "Ultimate"
    }

def validity2str(valid):
    "Convert trust integer into a human understandable string"
    if valid in trusts: return _("%s" % trusts[valid])
    else:                     return _("Unknown")

def keyvalid2str(key):
    "Create a string representing validity of a key"
    if key.owner_trust==validity.ULTIMATE:
        return _("Fully Valid")
    if key.revoked: return _("Revoked")
    if key.expired: return _("Expired")
    if key.disabled: return _("Disabled")
    if not key.uids or key.uids[0].invalid: return _("Incomplete")
    return _("Unknown")

def subvalid2str(subkey):
    "Create a string representing validity of a subkey"
    if subkey.revoked: return _("Revoked")
    if subkey.expired: return _("Expired")
    if subkey.disabled: return _("Disabled")
    if subkey.invalid: return _("Unsigned")
    return _("Valid")

def signstat2str(sig):
    "Create a string representing validity of a signature"
    status = _("Unknown")
    if sig.status == 1: status = _("Valid")
    elif sig.status == 2: status = _("Bad")
    if sig.expired: status = _("Expired")
    elif sig.revoked: status = _("Revoked")
    return status

def sigsum2str(summary):
    if summary & sigsum.VALID: return _("Valid")
    if summary & sigsum.RED: return _("Bad")
    if summary & sigsum.KEY_MISSING: return _("Unknown Key")
    if summary & sigsum.KEY_REVOKED: return _("Revoked Key")
    if summary & sigsum.KEY_EXPIRED: return _("Expired Key")
    return _("Key NOT valid")

def class2str(cls):
    "Convert signature class integer into a human understandable string"    
    if cls==0x10: return _("Generic")
    if cls==0x11: return _("Persona")
    if cls==0x12: return _("Casual")
    if cls==0x13: return _("Positive")
    return _("Unknown")

def algo2str(algo):
    "Convert algorithm integer into a human understandable string"
    return pubkey_algo_name(algo)

def fpr2str(fpr):
    "Convert fpr string in a sparsely spaced string for easy reading"
    result = []
    while fpr:
        result.append(fpr[:4])
        fpr = fpr[4:]
    return " ".join(result)

# Helper functions for tasks unrelated to any class
def obj2model(objs, columns):
    "Create a model from the obj (key, subkey, or signature) using columns"
    model = gtk.ListStore(*[x.ctype for x in columns])
    for obj in objs:
        model.append([x.cfunc(obj) for x in columns])
    return model

def labels2table(key_labels):
    "Create a gtk.Table from an array of 2-tuples of strings"
    table = gtk.Table(len(key_labels), 2)
    for i, row in enumerate(key_labels):
        if len(row) != 2:
            raise ValueError("Unexpected number of rows in labels2table call")
        label1 = gtk.Label(row[0])
        label1.set_alignment(1.0, 0.5)
        label2 = gtk.Label(row[1])
        label2.set_alignment(0.0, 0.5)
        label2.set_padding(5, 0)
        table.attach(label1, 0, 1, i, i+1, gtk.FILL, gtk.FILL)
        table.attach(label2, 1, 2, i, i+1, gtk.FILL, gtk.FILL)
    return table

status2str = {}
for name in dir(status):
    if not name.startswith('__') and name != "util":
        status2str[getattr(status, name)] = name

def editor_func(status, args, val_dict):
    prompt = "%s %s" % (val_dict["state"], args)
    if prompt in val_dict:
        val_dict["state"] = val_dict[prompt][0]
        return val_dict[prompt][1]
    elif args and "ignore %s" % status2str[status] not in val_dict:
        for error in ["error %s" % status2str[status], "error %s" % prompt]:
            if error in val_dict:
                raise errors.GPGMEError(val_dict[error])
        sys.stderr.write(_("Unexpected status and prompt in editor_func: " +
                           "%s %s\n") % (status2str[status], prompt))
        raise EOFError()
    return ""

common_dict = {
        "state": "start",
        "quit keyedit.save.okay": ("save", "Y"),
        "ignore NEED_PASSPHRASE": None,
        "ignore NEED_PASSPHRASE_SYM": None,
        "ignore BAD_PASSPHRASE": None,
        "ignore USERID_HINT": None
        }  

def change_key_expire(context, key, date):
    "Change key's expiration date to date"
    val_dict = common_dict.copy()
    val_dict.update({
        "start keyedit.prompt": ("expire", "expire"),
        "expire keygen.valid": ("date", date),
        "date keyedit.prompt": ("quit", "quit")
        })
    out = Data()
    context.op_edit(key, editor_func, val_dict, out)

def change_key_trust(context, key, new_trust):
    "Change key's trust to new_trust"
    val_dict = common_dict.copy()
    val_dict.update({
        "start keyedit.prompt": ("trust", "trust"),
        "trust edit_ownertrust.value": ("value", "%d" % new_trust),
        "value edit_ownertrust.set_ultimate.okay": ("value", "Y"),
        "value keyedit.prompt": ("quit", "quit")
        })
    out = Data()
    context.op_edit(key, editor_func, val_dict, out)

def sign_key(context, key, sign_key, local):
    "Sign key using sign_key. Signature is exportable if local is False"
    # Values copied from <gpg-error.h>
    GPG_ERR_CONFLICT = 70
    GPG_ERR_UNUSABLE_PUBKEY = 53
    val_dict = common_dict.copy()
    val_dict.update({
        "start keyedit.prompt": ("sign", (local and "lsign") or "sign"),
        "sign keyedit.sign_all.okay": ("sign", "Y"),
        "sign sign_uid.expire": ("sign", "Y"),
        "sign sign_uid.class": ("sign", "0"),
        "sign sign_uid.okay": ("okay", "Y"),
        "okay keyedit.prompt": ("quit", "quit"),
        "error ALREADY_SIGNED": GPG_ERR_CONFLICT,
        "error sign keyedit.prompt": GPG_ERR_UNUSABLE_PUBKEY
        })
    out = Data()
    context.signers_clear()
    context.signers_add(sign_key)
    context.op_edit(key, editor_func, val_dict, out)

def trigger_change_password(context, key):
    "Trigger sequence of passphrase_cb callbacks to change password of the key"
    val_dict = common_dict.copy()
    val_dict.update({
        "start keyedit.prompt": ("passwd", "passwd"),
        "passwd keyedit.prompt": ("quit", "quit")
        })
    out = Data()
    context.op_edit(key, editor_func, val_dict, out)

# Helper classes whose instances are used in the major PyGpa class
class KeyInfo:
    """Helper class to represent key information in different views.
    If KeyInfo instance is initialized with an integer as a key the views
    correspond to a state when multiple or no keys are selected"""
    def __init__(self, key, secret=None):
        self.key = key
        self.secret = secret

    def key_print_labels(self, fpr=False):
        "Create an array of 2-tuples for 'User Name' and 'Key ID' fields"
        labels = []
        if type(self.key) != int:
            if self.key.uids:
                labels.append((_("User Name:"), self.key.uids[0].uid))
		for uid in self.key.uids[1:]:
                    labels.append(("", uid.uid))
            if fpr:
                labels += [(_("Fingerprint:"), fpr2str(self.key.subkeys[0].fpr))]
            else:
                labels += [(_("Key ID:"), self.key.subkeys[0].keyid[-8:])]
        return labels

    def key_expires_label(self):
        return sec2str(self.key.subkeys[0].expires,_("never expires"))

    def details(self):
        "Create a widget for 'Details' notebook tab"
        if type(self.key) == int:
            if self.key:
                details=gtk.Label(_("%d keys selected") % self.key)
            else:
                details=gtk.Label(_("No keys selected"))
            details.set_alignment(0.5, 0)
            return details
        
        if self.secret:
            header = _("The key has both a private and a public part")
        else:
            header = _("The key has only a public part")
        key_info_labels = [("", header)]

        if self.key.can_certify:
            if self.key.can_sign:
                if self.key.can_encrypt:
                    ability = _("The key can be used for certification, " +
                                "signing and encryption.")
                else:
                    ability = _("The key can be used for certification and " +
                                "signing, but not for encryption.")
            else:
                if self.key.can_encrypt:
                    ability = _("The key can be used for certification and " +
                                "encryption.")
                else:
                    ability = _("The key can be used only for certification.")
        else:
            if self.key.can_sign:
                if self.key.can_encrypt:
                    ability = _("The key can be used only for signing and " +
                                "encryption, but not for certification.")
                else:
                    ability = _("The key can be used only for signing.")
            else:
                if self.key.can_encrypt:
                    ability = _("The key can be used only for encryption.")
                else:
                    ability = _("This key is useless.")
        key_info_labels.append(("", ability))

        key_info_labels += self.key_print_labels() + [
            (_("Fingerprint:"), fpr2str(self.key.subkeys[0].fpr)),
            (_("Expires at:"), self.key_expires_label()),
            (_("Owner Trust:"), validity2str(self.key.owner_trust)),
            (_("Key Validity:"), keyvalid2str(self.key)),
            (_("Key Type:"), _("%s %u bits") % \
             (algo2str(self.key.subkeys[0].pubkey_algo),self.key.subkeys[0].length)),
            (_("Created at:"), sec2str(self.key.subkeys[0].timestamp))
            ]

        return labels2table(key_info_labels)

    def sign_model(self):
        "Create a model for ComboBox of uids in 'Signatures' notebook tab"
        model = gtk.ListStore(str, gtk.ListStore)
        if type(self.key) != int:
            for uid in self.key.uids:
                model.append([uid.uid, obj2model(uid.signatures,sign_columns)])
        return model

    def subkey_model(self):
        "Create a model for TreeView in 'Subkeys' notebook tab"
        if type(self.key) == int:
            return gtk.ListStore(*[x.ctype for x in subkey_columns])
        else:
            return obj2model(self.key.subkeys, subkey_columns)

class Column:
    "Helper class to represent a column in a TreeView"
    def __init__(self, name, ctype, cfunc, detail=False):
        """Column(name, ctype, cfunc):
        name  - Name to use as a column header
        ctype - type to use in a model definition for this column
        cfunc - function retrieving column's infromation from an object
        detail- indicate if it's a detail visible only in detailed view"""
        self.name = name
        self.ctype = ctype
        self.cfunc = cfunc
        self.detail = detail

# Columns for the list of keys which can be used as default
def_keys_columns = [
    Column(_("Key ID"), str, lambda x,y: x.subkeys[0].keyid[-8:]),
    Column(_("User Name"), str,
           lambda x,y: (x.uids and x.uids[0].uid) or _("[Unknown user ID]")),
    Column(None, gobject.TYPE_PYOBJECT, lambda x,y: KeyInfo(x,y))
    ]

# Columns for the list of all keys in the keyring
keys_columns = [
    Column("", str, lambda x,y: (y and "sec") or "pub"),
    def_keys_columns[0],
    Column(_("Expiry Date"), str,
           lambda x,y: sec2str(x.subkeys[0].expires, _("never expires")), True),
    Column(_("Owner Trust"),str,lambda x,y:validity2str(x.owner_trust),True),
    Column(_("Key Validity"), str, lambda x,y: keyvalid2str(x), True)
    ] + def_keys_columns[1:]

# Columns for the list of signatures on a uid
sign_columns = [
    Column(_("Key ID"), str, lambda x: x.keyid[-8:]),
    Column(_("Status"), str, lambda x: signstat2str(x)),
    Column(_("Level"), str, lambda x: class2str(x.sig_class)),
    Column(_("Local"), type(True), lambda x: x.exportable==0),
    Column(_("User Name"), str, lambda x: x.uid or _("[Unknown user ID]"))
    ]

# Columns for the list of subkeys
subkey_columns = [
    Column(_("Subkey ID"), str, lambda x: x.keyid[-8:]),
    Column(_("Status"), str, lambda x: subvalid2str(x)),
    Column(_("Algorithm"), str, lambda x: algo2str(x.pubkey_algo)),
    Column(_("Size"), str, lambda x: _("%u bits") % x.length),
    Column(_("Expiry Date"), str,
           lambda x: sec2str(x.expires, _("never expires"))),
    Column(_("Can sign"), type(True), lambda x: x.can_sign),
    Column(_("Can certify"), type(True), lambda x: x.can_certify),
    Column(_("Can encrypt"), type(True), lambda x: x.can_encrypt),
    Column(_("Can authenticate"), type(True), lambda x: x.can_authenticate)
    ]

file_columns = [
    Column(_("File"), str, lambda x: x)
    ]

class PyGpa:
    "Major class representing PyGpa application"
    def popup(self, dialog, parent=None, title=None):
        "Common way to popup a dialog defined in Glade"
        dialog.set_transient_for(parent or self.main_window)
        if title: dialog.set_title(title)
        result = dialog.run()
        dialog.hide()
        return result

    def file_popup(self, dialog, parent=None, title=None):
        return self.popup(dialog, parent or self.filemanager_window, title)
        
    def error_message(self, text, parent=None, title=_("Warning")):
        "Pop up an error message dialog"
        if type(text) == int:
            text = errors.GPGMEError(text).getstring()
            title = "GPGME error"
        elif isinstance(text, errors.GPGMEError):
            text = text.getstring()
            title = "GPGME error"
        self.error_label.set_text(text)
        self.popup(self.error_dialog, parent, title)

    def file_error_message(self, text, parent=None, title=_("Warning")):
        self.error_message(text, parent or self.filemanager_window, title)

    def info_message(self, text, parent=None, title=_("Information")):
        "Pop up an information dialog"
        self.info_label.set_text(text)
        self.popup(self.info_dialog, parent, title)

    def yesno_message(self, text, parent=None):
        "Pop up a dialog requiring yes/no answer"
        self.yesno_label.set_text(text)
        return self.popup(self.yesno_dialog, parent,
                          _("Warning")) == gtk.RESPONSE_YES

    def on_uid_list_changed(self, uid_list):
        "this callback is called when uid selection is changed"
        index = uid_list.get_active()
        if index == -1:
            self.sign_treeview.set_model(KeyInfo(0).sign_model())
        else:
            self.sign_treeview.set_model(uid_list.get_model()[index][1])

    def get_selected_keys(self, treeview=None):
        "Helper function to get all selected rows in a treeview"
        if not treeview:
            treeview = self.keys_treeview
        model, rows = treeview.get_selection().get_selected_rows()
        return [model[path] for path in rows]

    def on_keys_changed(self, keys_treeview):
        "this callback is called when key selection is changed"
        selection = keys_treeview.get_selection()
        count = selection.count_selected_rows()
        if count == 1:
            key_info = self.get_selected_keys()[0][-1]
        else:
            key_info = KeyInfo(count)

        self.update_menu(key_info)

        # Update Details tab of the notebook
        old_child = self.details_view.get_child()
        if old_child: self.details_view.remove(old_child)
        self.details_view.add(key_info.details())
        self.details_view.show_all()

        # Update Subkeys tab of the notebook
        self.subkeys_treeview.set_model(key_info.subkey_model())

        # Update Signatures tab of the notebook
        sign_model = key_info.sign_model()
        self.uid_list.set_model(sign_model)
        if len(sign_model) < 2:
            self.uid_list_box.hide()
        else:
            self.uid_list_box.show_all()
        self.uid_list.set_active(0)
        self.on_uid_list_changed(self.uid_list)

    def on_keys_button_press(self, obj, event):
        "callback on a mouse press in the keys_treeview"
        if event.button == 3:
            self.popup_menu.popup(None, None, None, event.button, event.time)
            return True
        return False

    def create_popup_menu(self):
        "create the popup menu shown on right mouse click"
        self.items = [
            (gtk.ImageMenuItem(gtk.STOCK_COPY), self.on_copy_activate),
            (gtk.ImageMenuItem(gtk.STOCK_PASTE), self.on_paste_activate),
            (gtk.ImageMenuItem(gtk.STOCK_DELETE), self.on_delete_activate),
            (gtk.SeparatorMenuItem(), None),
            (gtk.MenuItem(_("_Sign Keys...")), self.on_sign_keys_activate),
            (gtk.MenuItem(_("Set _Owner Trust...")),
             self.on_set_owner_trust_activate),
            (gtk.MenuItem(_("_Edit Private Key...")),
             self.on_edit_private_key_activate),
            (gtk.SeparatorMenuItem(), None),
            (gtk.MenuItem(_("E_xport Keys...")), self.on_export_keys_activate)
            ]
        self.popup_menu = gtk.Menu()
        for item, callback in self.items:
            if callback: item.connect("activate", callback)
            self.popup_menu.append(item)
        self.popup_menu.show_all()        
    
    def update_menu(self, key_info):
        "update sensitivity of menu items depending on what keys are selected"
        #                  copy, delete, sign, trust, edit, export
        if key_info.secret == None:
            if key_info.key:            # more than one key selected
                values = ( True,  True,  True, False, False,  True)
            else:                       # no keys selected
                values = (False, False, False, False, False, False)
        elif key_info.secret:
            if key_info.key == self.default_key: # default key seleted
                values = ( True,  True, False,  True,  True,  True)
            else:                       # secret (not default) key selected
                values = ( True,  True,  True,  True,  True,  True)
        else:                           # public key selected
            values   =   ( True,  True,  True,  True, False,  True)

        for w,v in zip((self.copy, self.delete, self.sign_keys,
                        self.set_owner_trust, self.edit_private_key,
                        self.export_keys), values):
            w.set_sensitive(v)
        for w,v in zip((self.items[0][0], self.items[2][0], self.items[4][0],
                        self.items[5][0], self.items[6][0], self.items[8][0]),
                       values):
            w.set_sensitive(v)                
    
    def setup_columns(self):
        "Helper function to setup columns of different treeviews"
        for treeview, columns in \
                [(self.keys_treeview, keys_columns),
                 (self.sign_treeview, sign_columns),
                 (self.subkeys_treeview, subkey_columns),
                 (self.def_keys_treeview, def_keys_columns),
                 (self.sign_with_keys_treeview, def_keys_columns),
                 (self.encrypt_with_keys_treeview, def_keys_columns),
                 (self.files_treeview, file_columns)]:
            for index, item in enumerate([x for x in columns if x.name!=None]):
                if item.ctype == str:
                    renderer = gtk.CellRendererText()
                    attrs = {"text": index}
                else:
                    renderer = gtk.CellRendererToggle()
                    attrs = {"active": index}
                column = treeview.insert_column_with_attributes(
                    index, item.name, renderer, **attrs)
                column.set_sort_column_id(index)
                column.set_visible(not item.detail)

        for index,item in enumerate([x for x in keys_columns if x.name!=None]):
            if item.name and not item.detail:
                renderer = gtk.CellRendererText()
                column = gtk.TreeViewColumn(item.name, renderer, text=index)
                column.set_sort_column_id(index)
                self.encrypt_for_keys_treeview.append_column(column)

        for treeview in [self.encrypt_with_keys_treeview, self.keys_treeview,
                         self.encrypt_for_keys_treeview, self.files_treeview,
                         self.sign_with_keys_treeview]:
            treeview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        self.def_keys_treeview.get_selection().set_mode(gtk.SELECTION_SINGLE)

        cell = gtk.CellRendererText()
        self.uid_list.pack_start(cell, True)
        self.uid_list.add_attribute(cell, 'text', 0)

        model = gtk.ListStore(str, str)
        for lines in [(_("days"), "d"), (_("weeks"), "w"),
                      (_("months"), "m"), (_("years"), "y")]:
            model.append(lines)
        self.new_expire_unit_combo.set_model(model)
        self.new_expire_unit_combo.child.set_editable(False)
        self.new_algorithm_combo.child.set_editable(False)

        self.files_treeview.set_model(gtk.ListStore(str))

    def setup_default_views(self):
        "Setup initial values for different views"
        self.update_default_keys()
        self.on_advanced_mode_toggled(self.advanced_mode_rb)
        self.create_popup_menu()
        self.on_keys_changed(self.keys_treeview)

    def load_keys(self):
        "Download keys from the keyring"
        context = Context()
        sec_keys = {}
        for key in context.op_keylist_all(None, 1):
            sec_keys[key.subkeys[0].fpr] = 1
        model = gtk.ListStore(*[x.ctype for x in keys_columns])
        encrypt_model = gtk.ListStore(*[x.ctype for x in keys_columns])
        context.set_keylist_mode(keylist.mode.SIGS)
        for key in context.op_keylist_all(None, 0):
            secret = key.subkeys[0].fpr in sec_keys
            data = [x.cfunc(key, secret) for x in keys_columns]
            if key.can_encrypt: encrypt_model.append(data)
            model.append(data)
        self.keys_treeview.set_model(model)
        self.encrypt_for_keys_treeview.set_model(encrypt_model)

    def set_default_key(self, key):
        "Setup default key and update status bar with it"
        self.default_key = key
        self.status_uid.set_text((key.uids and key.uids[0].uid) or \
                                 _("[Unknown user ID]"))
        self.status_keyid.set_text(key.subkeys[0].keyid[-8:])

    def on_default_keys_changed(self, treeview):
        "This callback is called when default key is changed in Preferences"
        model, rows = treeview.get_selection().get_selected_rows()
        if model and rows:
            self.set_default_key(model[rows[0]][-1].key)

    def add_default_key(self, model, path, iter, def_model):
        "Helper function to add secret keys to the list of possible defaults"
        key = model[path][-1]
        if key.secret:
            def_model.append([x.cfunc(key.key,True) for x in def_keys_columns])

    def add_sig_key(self, model, path, iter, sign_model):
        "Helper function to add secret keys to the list of possible defaults"
        key = model[path][-1].key
        if key.can_sign:
            sign_model.append([x.cfunc(key,True) for x in def_keys_columns])

    def select_default_key(self, model, path, iter):
        "Helper function to select current default key from the available list"
        if model[path][-1].key == self.default_key:
            self.def_keys_treeview.get_selection().select_path(path)

    def update_default_keys(self):
        "Update list of default keys"
        model = gtk.ListStore(*[x.ctype for x in def_keys_columns])
        self.keys_treeview.get_model().foreach(self.add_default_key, model)
        self.def_keys_treeview.set_model(model)
        model.foreach(self.select_default_key)
        selection = self.def_keys_treeview.get_selection()
        if selection.count_selected_rows() != 1:
            selection.select_path((0,))
            self.on_default_keys_changed(self.def_keys_treeview)
        model = gtk.ListStore(*[x.ctype for x in def_keys_columns])
        self.def_keys_treeview.get_model().foreach(self.add_sig_key, model)
        self.sign_with_keys_treeview.set_model(model)
        self.encrypt_with_keys_treeview.set_model(model)

    def on_select_all_activate(self, obj):
        "This callback is called when SelectAll menu item is selected"
        self.keys_treeview.get_selection().select_all()

    def on_file_preferences_activate(self, obj):
        "Callback called when Preferences menu item is selected in filemanager"
        self.show_preferences(self.filemanager_window)

    def on_preferences_activate(self, obj):
        "Callback called when Preferences menu item is selected in key editor"
        self.show_preferences(None)

    def show_preferences(self, parent):
        "Show preferences positioning its window in the middle of the parent"
        self.popup(self.preferences_dialog, parent)
        self.def_keyserver = self.default_keyserver_combox.child.get_text()

    def on_advanced_mode_toggled(self, radiobutton):
        "This callback is called when Advanced Mode selection is changed"
        if radiobutton.get_active():
            self.subkeys_notebook_tab.show()
            self.get_generate_params = self.get_advanced_generate_params
        else:
            self.subkeys_notebook_tab.hide()
            self.get_generate_params = self.get_novice_generate_params

    def popup_progress_dialog(self, label, parent):
        self.progress_dialog.set_transient_for(parent)
        self.progress_label.set_text(label)
        self.progress_dialog.show_all()
        gobject.timeout_add(100, self.update_progress)

    def on_progress_cancel_clicked(self, obj):
        self.progress_context.cancel()

    def update_progress(self):
        "Helper function to show progress while a work on a key is being done"
        try:
            status = self.progress_context.wait(0)
            if status == None or self.progress_func(status):
                self.new_progressbar.pulse()
                return True
        except errors.GPGMEError as exc:
            self.error_message(exc)
        
        self.progress_context = None
        self.progress_func = None
        self.progress_dialog.hide()

        # Let callback to be removed.
        return False

    def key_generate_done(self, status):
        "Helper function called on the completion of a key generation"
        if status == 0:
            fpr = self.progress_context.op_genkey_result().fpr
            self.progress_context.set_keylist_mode(keylist.mode.SIGS)
            key = self.progress_context.get_key(fpr, 0)
            data = [x.cfunc(key, True) for x in keys_columns]
            self.keys_treeview.get_model().append(data)
            if key.can_encrypt:
                self.encrypt_for_keys_treeview.get_model().append(data)
            self.update_default_keys()
        else:
            self.error_message(status)
        return False

    def on_new_activate(self, obj):
        "Callback for 'New Key' menu item"
        params = self.get_generate_params()
        if params == None:
            return

        (key_algo, subkeys, size, userid, email,
         comment, expire, password, backup) = params

        gen_string = "<GnupgKeyParms format=\"internal\">\n" + \
                         "Key-Type: %s\n" % key_algo + \
                         "Key-Length: %d\n" % size
        if subkeys:
            gen_string += "Subkey-Type: %s\n" % subkeys + \
                          "Subkey-Length: %d\n" % size
        gen_string += "Name-Real: %s\n" % userid
        if email:
            gen_string += "Name-Email: %s\n" % email
        if comment:
            gen_string += "Name-Comment: %s\n" % comment
        if expire:
            gen_string += "Expire-Date: %s\n" % expire
        if password:
            gen_string += "Passphrase: %s\n" % password
        gen_string += "</GnupgKeyParms>\n"

        self.progress_context = Context()
        self.progress_context.op_genkey_start(gen_string, None, None)
        self.progress_func = self.key_generate_done
        self.popup_progress_dialog(_("Generating Key..."), self.main_window)

    def check_passphrase(self, passphrase, repeat_passphrase, parent):
        """Helper function to check that enetered password satisfies our
        requirements"""
        if not passphrase:
            self.error_message(_('You did not enter a passphrase.\n' +
                                 'It is needed to protect your private key.'),
                               parent)
        elif repeat_passphrase != passphrase:
            self.error_message(_('In "Passphrase" and "Repeat passphrase",\n' +
                                 'you must enter the same passphrase.'),
                               parent)
        else:
            return True
        return False

    def get_novice_generate_params(self):
        "Helper function to get generate key parameter in Novice mode"
        dialogs = [self.generate_userid_dialog,
                   self.generate_email_dialog,
                   self.generate_comment_dialog,
                   self.generate_passphrase_dialog,
                   self.generate_backup_dialog]
        step = 0
        params = None
        while step>=0:
            dialog = dialogs[step]
            dialog.set_transient_for(self.main_window)
            result = dialog.run()
            newstep = step
            if result == 2:
                if step == 0:
                    userid = self.generate_novice_userid_entry.get_text()
                    if userid: newstep = step + 1
                    else: self.error_message(_("Please insert your name."))
                elif step == 1:
                    email = self.generate_novice_email_entry.get_text()
                    if email: newstep = step + 1
                    else:
                        self.error_message(_("Please insert your email address"))
                elif step == 2:
                    comment = self.generate_novice_comment_entry.get_text()
                    newstep = step + 1
                elif step == 3:
                    passphrase=self.generate_novice_passphrase_entry.get_text()
                    if self.check_passphrase(
                        passphrase,
                        self.generate_novice_repeat_passphrase_entry.get_text(),
                        dialog):
                        newstep = step + 1
                elif step == 4:
                    backup = self.generate_novice_backup_rb.get_active()
                    params = ("DSA", "ELG-E", 1024, userid, email,
                              comment, "", passphrase, backup)
                    newstep = -1
            elif result == 1:
                newstep = step - 1
            else:
                newstep = -1

            if newstep != step:
                dialog.hide()
                step = newstep

        self.generate_novice_userid_entry.set_text("")
        self.generate_novice_email_entry.set_text("")
        self.generate_novice_comment_entry.set_text("")
        self.generate_novice_passphrase_entry.set_text("")
        self.generate_novice_repeat_passphrase_entry.set_text("")
        return params

    def on_new_expire_on_rb_toggled(self, expireon_rb):
        self.new_expire_calendar.set_sensitive(expireon_rb.get_active())

    def on_new_expire_after_rb_toggled(self, expireafter_rb):
        active = expireafter_rb.get_active()
        self.new_expire_count_entry.set_sensitive(active)
        self.new_expire_unit_combo.set_sensitive(active)

    def get_advanced_generate_params(self):
        "Helper function to get generate key parameter in Advanced mode"
        params = None
        self.new_expire_unit_combo.set_active(0)
        self.new_algorithm_combo.set_active(0)
        self.new_key_size_combo.set_active(1)
        self.generate_dialog.set_transient_for(self.main_window)
        while params == None and self.generate_dialog.run() == gtk.RESPONSE_OK:
            passphrase = self.new_passphrase_entry.get_text()
            if not self.check_passphrase(
                passphrase,
                self.new_repeat_passphrase_entry.get_text(),
                self.generate_dialog):
                continue
            key_algo, subkeys = {
                'DSA and ElGamal (default)': ("DSA", "ELG-E"),
                'DSA (sign only)': ("DSA", ""),
                'RSA (sign only)': ("RSA", "")
                }[self.new_algorithm_combo.child.get_text()]
            try:
                size = int(self.new_key_size_combo.child.get_text())
            except ValueError:
                self.new_key_size_combo.child.grab_focus()
                continue
            userid = self.new_userid_entry.get_text()
            email = self.new_email_entry.get_text()
            comment = self.new_comment_entry.get_text()
            expire = ""
            if self.new_expire_after_rb.get_active():
                model = self.new_expire_unit_combo.get_model()
                unit = model[(self.new_expire_unit_combo.get_active(),)][1]
                try:
                    value = int(self.new_expire_count_entry.get_text())
                except ValueError:
                    self.new_expire_count_entry.grab_focus()
                    continue
                expire = "%d%s" % (value, unit)
            elif self.new_expire_on_rb.get_active():
                (year, month, day) = self.new_expire_calendar.get_date()
                expire = "%04d-%02d-%02d" % (year, month+1, day)
            params = (key_algo, subkeys, size, userid, email,
                      comment, expire, passphrase, False)
        self.generate_dialog.hide()
        self.new_passphrase_entry.set_text("")
        self.new_repeat_passphrase_entry.set_text("")
        return params

    def del_key(self, key, treeview):
        "Helper function to delete a key from a treeview list"
        row_list = []
        treeview.get_model().foreach(lambda m,p,i,l: l.append(m[p]), row_list)
        for row in row_list:
            if row[-1].key.subkeys[0].fpr == key.subkeys[0].fpr:
                row.model.remove(row.iter)

    def on_delete_activate(self, obj):
        "Callback for 'Delete Keys' menu item"
        message = {
            True:  _("This key has a secret key. Deleting this key cannot be"+
                     " undone, unless you have a backup copy."),
            False: _("This key is a public key. Deleting this key cannot be "+
                     "undone easily, although you may be able to get a new " +
                     "copy  from the owner or from a key server.")
            }
        keytag = self.delete_key_keyinfo
        for row in self.get_selected_keys():
            self.delete_key_label.set_text(message[row[-1].secret])
            table = labels2table(row[-1].key_print_labels())
            keytag.add(table)
            keytag.show_all()
            if self.popup(self.delete_key_dialog) == gtk.RESPONSE_YES:
                context = Context()
                context.op_delete(row[-1].key, 1)
                if row[-1].key.can_encrypt:
                    self.del_key(row[-1].key, self.encrypt_for_keys_treeview)
                row.model.remove(row.iter)
                self.update_default_keys()
                self.on_keys_changed(self.keys_treeview)
            keytag.remove(table)

    def password_cb(self, hint, desc, prev_bad, hook=None):
        "Callback to setup verification of a passphrase"
        if prev_bad:
            header = _("Wrong passphrase, please try again:")
        else:
            header = _("Please enter the passphrase for the following key:")
        self.password_prompt_label.set_text(header)
        keyid, userid = hint.split(" ", 1)
        table = labels2table([(_("User Name:"), userid),
                              (_("Key ID:"), keyid[-8:])])
        self.password_prompt_keyinfo.add(table)
        self.password_prompt_keyinfo.show_all()
        password = None
        if self.popup(self.password_prompt_dialog) == gtk.RESPONSE_OK:
            password = self.password_prompt_entry.get_text()
        self.password_prompt_keyinfo.remove(table)
        self.password_prompt_entry.set_text("")
        if not password:
            GPG_ERR_CANCELED = 99
            raise errors.GPGMEError(GPG_ERR_CANCELED)
        return password

    def password_change_cb(self, hint, desc, prev_bad, hook):
        "Callback to setup for passphrase change"
        if not prev_bad:
            hook["count"] += 1
            
        if hook["count"] == 1:
            return self.password_cb(hint, desc, prev_bad)
        else:
            password = None
            self.password_change_dialog.set_transient_for(self.main_window)
            while password == None and \
                      self.password_change_dialog.run() == gtk.RESPONSE_OK:
                password = self.password_change_passphrase.get_text()
                if not self.check_passphrase(
                    password,
                    self.password_change_repeat_passphrase.get_text(),
                    self.password_change_dialog):
                    password = None
            self.password_change_dialog.hide()
            self.password_change_passphrase.set_text("")
            self.password_change_repeat_passphrase.set_text("")
            if not password:
                GPG_ERR_CANCELED = 99
                raise errors.GPGMEError(GPG_ERR_CANCELED)
            return password

    def on_sign_keys_activate(self, obj):
        "Callback for 'Sign keys' menu item"
        context = Context()
        context.set_passphrase_cb(self.password_cb)
        context.set_keylist_mode(keylist.mode.SIGS)
        keytag = self.sign_key_keyinfo
        for row in self.get_selected_keys():
            if row[-1].key == self.default_key:
                continue
            if len(row[-1].key.uids) > 1:
                self.sign_manyuids_label.show()
            else:
                self.sign_manyuids_label.hide()
            table = labels2table(row[-1].key_print_labels(True))
            keytag.add(table)
            keytag.show_all()
            if self.popup(self.sign_key_dialog) == gtk.RESPONSE_YES:
                try:
                    sign_key(context, row[-1].key, self.default_key,
                             self.sign_locally_cb.get_active())
                    row[-1].key=context.get_key(row[-1].key.subkeys[0].fpr,0)
                    self.on_keys_changed(self.keys_treeview)
                except errors.GPGMEError as exc:
                    self.error_message(exc)
            keytag.remove(table)

    def on_change_passphrase_clicked(self, obj, key_info):
        "Callback for 'Change passphrase' button in editor for a private key"
        try:
            context = Context()
            context.set_passphrase_cb(self.password_change_cb, {"count": 0})
            trigger_change_password(context, key_info.key)
        except errors.GPGMEError as exc:
            self.error_message(exc)

    def on_change_expiry_expireon_rb_toggled(self, expire_rb):
        "Callback for 'never expire' radiobutton in editor for a private key"
        self.change_expiry_calendar.set_sensitive(expire_rb.get_active())

    def on_change_expiration_clicked(self, obj, key_info):
        "Callback for 'Change expiration' button in editor for a private key"
        if key_info.key.subkeys[0].expires:
            year, month, day = time.localtime(key_info.key.subkeys[0].expires)[:3]
            self.change_expiry_calendar.select_month(month-1, year)
            self.change_expiry_calendar.select_day(day)
            self.change_expiry_expireon_rb.set_active(True)
        else:
            self.change_expiry_never_rb.set_active(True)
        if self.popup(self.change_expiry_dialog,
                      self.edit_key_dialog) == gtk.RESPONSE_OK:
            year, month, day = self.change_expiry_calendar.get_date()
            expire = "%04d-%02d-%02d" % (year, month+1, day)
            try:
                context = Context()
                context.set_passphrase_cb(self.password_cb)
                change_key_expire(context, key_info.key, expire)
                context.set_keylist_mode(keylist.mode.SIGS)
                key_info.key=context.get_key(key_info.key.subkeys[0].fpr,0)
                self.on_keys_changed(self.keys_treeview)
                self.edit_key_date_label.set_text(key_info.key_expires_label())
            except errors.GPGMEError as exc:
                self.error_message(exc)

    def on_edit_private_key_activate(self, obj):
        "Callback for 'Edit Private Key' menu item"
        keys = self.get_selected_keys()
        if len(keys) != 1 or not keys[0][-1].secret:
            return
        
        key_info = keys[0][-1]
        table = labels2table(key_info.key_print_labels())
        self.edit_key_date_label.set_text(key_info.key_expires_label())
        self.edit_key_keyinfo.add(table)
        self.edit_key_keyinfo.show_all()
        connect1_id = self.edit_key_change_expiration.connect(
            "clicked", self.on_change_expiration_clicked, key_info)
        connect2_id = self.edit_key_change_passphrase.connect(
            "clicked", self.on_change_passphrase_clicked, key_info)
        self.popup(self.edit_key_dialog)
        self.edit_key_change_expiration.disconnect(connect1_id)
        self.edit_key_change_passphrase.disconnect(connect2_id)
        self.edit_key_keyinfo.remove(table)

    def on_set_owner_trust_activate(self, obj):
        "Callback for 'Set Owner Trust' menu item"
        keys = self.get_selected_keys()
        if len(keys) != 1:
            return

        key_info = keys[0][-1]
        table = labels2table(key_info.key_print_labels())
        self.ownertrust_key.add(table)
        self.ownertrust_key.show_all()
        trust = key_info.key.owner_trust
        if trust < 0 or trust not in trusts:
            trust = validity.UNDEFINED
        getattr(self, "ownertrust_"+trusts[trust]).set_active(True)
        if self.popup(self.ownertrust_dialog) == gtk.RESPONSE_OK:
            for trust, name in trusts.items():
                if getattr(self, "ownertrust_"+name).get_active():
                    try:
                        context = Context()
                        change_key_trust(context, key_info.key, trust)
                        key_info.key.owner_trust = trust
                        self.on_keys_changed(self.keys_treeview)
                    except errors.GPGMEError as exc:
                        self.error_message(exc)            
                    break
        self.ownertrust_key.remove(table)

    def import_keys_from_data(self, data):
        "Helper function to import keys into application from a Data() object"
        context = Context()
        status = context.op_import(data)
        if status:
            self.error_message(status)
        else:
            result = context.op_import_result()
            if result.considered == 0:
                self.error_message(_("No keys were found."))
            else:
                self.load_keys()
                self.info_message(_("%i public keys read\n" +
                                    "%i public keys imported\n" +
                                    "%i public keys unchanged\n" +
                                    "%i secret keys read\n" +
                                    "%i secret keys imported\n" +
                                    "%i secret keys unchanged") % \
                                  (result.considered,
                                   result.imported,
                                   result.unchanged,
                                   result.secret_read,
                                   result.secret_imported,
                                   result.secret_unchanged))

    def import_from_clipboard(self, clipboard, text, data):
        "Callback to setup extraction of data from a clipboard"
        if text:
            self.import_keys_from_data(Data(text))

    def on_paste_activate(self, obj):
        "Callback for 'Paste' menu item"
        gtk.clipboard_get().request_text(self.import_from_clipboard)

    def on_import_keys_activate(self, obj):
        "Callback for 'Import Keys' menu item"
        import_file = None
        dialog = self.import_file_dialog
        dialog.set_transient_for(self.main_window)
        while import_file == None and dialog.run() == gtk.RESPONSE_OK:
            try:
                import_file = open(dialog.get_filename(), "rb")
            except IOError as strerror:
                self.error_message(strerror, dialog)
                import_file = None
        dialog.hide()
        if import_file != None:
            self.import_keys_from_data(Data(file=import_file))
            import_file.close()

    def export_selected_keys(self, armor):
        "Helper function to export selected keys into a Data() object"
        context = Context()
        context.set_armor(armor)
        export_keys = Data()
        for row in self.get_selected_keys():
            context.op_export(row[-1].key.subkeys[0].fpr, 0, export_keys)
        export_keys.seek(0,0)
        return export_keys
        
    def on_copy_activate(self, obj):
        "Callback for 'Copy' menu item"
        if self.keys_treeview.get_selection().count_selected_rows() > 0:
            export_keys = self.export_selected_keys(True)
            gtk.clipboard_get().set_text(export_keys.read())

    def verify_output(self, filename, parent):
        "Helper function to verify that user can write into the filename"
        if os.path.exists(filename):
            if os.path.isdir(filename):
                self.error_message(_("%s is a directory")%filename, parent)
                return False
            else:
                return self.yesno_message(_("The file %s already exists.\n" +
                                            "Do you want to overwrite it?") %
                                          filename, parent)
        return True
        
    def on_export_keys_activate(self, obj):
        "Callback for 'Export Keys' menu item"
        if self.keys_treeview.get_selection().count_selected_rows() < 1:
            return

        export_file = None
        dialog = self.export_file_dialog
        dialog.set_transient_for(self.main_window)
        while export_file == None and dialog.run() == gtk.RESPONSE_OK:
            filename = dialog.get_filename()
            if self.verify_output(filename, dialog):
                try:
                    export_file = open(filename, "wb")
                except IOError as strerror:
                    self.error_message(strerror, dialog)
                    export_file = None
        dialog.hide()
        if export_file == None:
            return

        export_keys = self.export_selected_keys(export_armor_cb.get_active())
        export_file.write(export_keys.read())
        export_file.close()                

    def on_files_changed(self, obj):
        "Callback called when selection of files in filemanager is changed"
        if self.files_treeview.get_selection().count_selected_rows() < 1:
            value = False
        else:
            value = True
        for item in (self.sign, self.verify, self.encrypt, self.decrypt):
            item.set_sensitive(value)

    def open(self, filename, complain=False):
        "Helper function to add a file into filemanager treeview"
        model = self.files_treeview.get_model()
        row_list = []
        model.foreach(lambda m,p,i,l: l.append(m[p][0]), row_list)
        if filename in row_list:
            if complain:
                self.file_error_message(_("The file is already open."))
        else:
            item = model.append([filename])
            self.files_treeview.get_selection().select_iter(item)
            self.on_files_changed(None)        

    def on_open_activate(self, obj):
        "Callback for 'Open' menu item"
        if self.file_popup(self.open_file_dialog) == gtk.RESPONSE_OK:
            self.add_file(self.open_file_dialog.get_filename(), True)
        self.open_file_dialog.unselect_all()

    def get_selected_files(self):
        "Helper function to return selected rows in filemanager treeview"
        return self.get_selected_keys(self.files_treeview)

    def on_clear_activate(self, obj):
        "Callback for 'Clear' menu item"
        for row in self.get_selected_files():
            row.model.remove(row.iter)

    def process_file_start(self, in_name, out_name):
        "Helper function to start asynchronous processing of one file"
        if self.verify_output(out_name, self.filemanager_window):
            try:
                self.in_data = Data(file=in_name)
                self.out_data = Data()
                self.out_name = out_name
                self.file_func(self.in_data, self.out_data)
            except errors.GPGMEError as exc:
                self.file_error_message(exc)

    def process_file_done(self, status):
        "The function called when asynchronous processing of the file is done."
        try:
            errors.errorcheck(status)
            self.out_data.seek(0,0)
            out_file = file(self.out_name, "wb")
            out_file.write(self.out_data.read())
            out_file.close()
            self.add_file(self.out_name)
            if self.file_list:
                self.process_file_start(*(self.file_list.pop(0)))
                return True
        except (errors.GPGMEError, IOError) as exc:
            self.file_error_message(exc)

        # Let python to free the memory.
        self.out_data = None
        self.in_data = None
        self.out_name = None
        self.file_list = []
        self.file_func = None
        return False

    def process_files_async(self, file_list, func, label):
        "Helper function to initialize async processing of the file list"
        self.file_list = file_list
        self.file_func = func
        self.progress_func = self.process_file_done
        self.process_file_start(*(self.file_list.pop(0)))
        self.popup_progress_dialog(label, self.filemanager_window)

    def on_sign_activate(self, obj):
        "Callback for 'Sign' menu item"
        files = self.get_selected_files()
        if not files: return
        
        if self.file_popup(self.sign_dialog) == gtk.RESPONSE_OK:
            context = Context()
            context.set_passphrase_cb(self.password_cb)
            context.set_armor(self.sign_armor_cb.get_active())
            for rw in self.get_selected_keys(self.sign_with_keys_treeview):
                context.signers_add(rw[-1].key)
            for cb,md,ext in [(self.sign_normal, sig.mode.NORMAL, ".gpg"),
                              (self.sign_clear, sig.mode.CLEAR, ".asc"),
                              (self.sign_separate,sig.mode.DETACH,".sig")]:
                if cb.get_active():
                    sigmode = md
                    sigext = ext
                    break
            self.progress_context = context
            def sign(x,y):self.progress_context.op_sign_start(x,y,sigmode)
            self.process_files_async([(f[0], f[0]+sigext) for f in files],
                                     sign, _("Signing..."))

    def verify_file_start(self, in_name, out_name):
        "Helper function to start file signature verification process"
        try:
            self.in_name = in_name
            self.out_name = out_name
            self.signed = Data(file=self.in_name)
            if out_name:
                self.plain1 = Data(file=self.out_name)
                self.plain2 = None
            else:
                self.plain1 = None
                self.plain2 = Data()
            self.progress_context.op_verify_start(self.signed, self.plain1,
                                                  self.plain2)
        except errors.GPGMEError as exc:
            self.file_error_message(exc)

    def verify_file_done(self, status):
        "The function called when asynchronous file signature verify is done."
        try:
            errors.errorcheck(status)
            result = self.progress_context.op_verify_result()

            model = gtk.ListStore(str, str, str)
            treeview = gtk.TreeView(model)
            treeview.set_rules_hint(True)
            for index, title in enumerate([_("Key ID"), _("Status"),
                                           _("User Name")]):
                treeview.append_column(gtk.TreeViewColumn(
                    title, gtk.CellRendererText(), text=index))
            for sign in result.signatures:
                key = self.progress_context.get_key(sign.fpr, 0)
                if key and key.uids:
                    keyid = key.subkeys[0].keyid[-8:]
                    userid = key.uids[0].uid
                else:
                    keyid = sign.fpr[-8:]
                    userid = _("[Unknown user ID]")
                model.append([keyid, sigsum2str(sign.summary), userid])
                    
            vbox = gtk.VBox()
            if self.out_name:
                vbox.add(gtk.Label(_("Verified data in file: %s") %
                                   self.out_name))
            label = gtk.Label(_("Signatures:"))
            label.set_alignment(0, 1)
            vbox.add(label)
            vbox.add(treeview)
            self.verified.append((vbox, gtk.Label(self.in_name)))
            if self.file_list:
                self.verify_file_start(*(self.file_list.pop(0)))
                return True
        except errors.GPGMEError as exc:
            self.file_error_message(exc)

        # Let python to free the memory.
        self.signed = None
        self.plain1 = None
        self.plain2 = None
        self.in_name = None
        self.out_name = None
        self.file_list = []
        self.progress_dialog.hide()
        
        if self.verified:
            notebook = gtk.Notebook()
            for page in self.verified: notebook.append_page(*page)
            self.verify_result.add(notebook)
            self.verify_result.show_all()
            self.file_popup(self.verify_dialog)
            self.verify_result.remove(notebook)
            self.verified = []
        
        return False

    def on_verify_activate(self, obj):
        "Callback for 'Verify' menu item"
        files = self.get_selected_files()
        if not files: return
        
        self.file_list = []
        for onefile in files:
            in_name = onefile[0]
            if in_name[-4:] == ".sig":
                out_name = in_name[:-4]
            elif in_name[-5:] == ".sign":
                out_name = in_name[:-5]
            else:
                out_name = None
            self.file_list.append((in_name, out_name))
        self.verified = []
        self.progress_context = Context()
        self.progress_func = self.verify_file_done
        self.verify_file_start(*(self.file_list.pop(0)))
        self.popup_progress_dialog(_("Verifying..."), self.filemanager_window)

    def on_encrypt_sign_toggled(self, cb):
        "Callback for change of the 'Sign' check box in 'Encrypt files' dialog"
        self.encrypt_with_keys_treeview.set_sensitive(cb.get_active())

    def on_encrypt_activate(self, obj):
        "Callback for 'Encrypt' menu item"
        files = self.get_selected_files()
        if not files: return
        
        self.on_encrypt_sign_toggled(self.encrypt_sign_cb)
        if self.file_popup(self.encrypt_dialog) == gtk.RESPONSE_OK:
            context = Context()
            context.set_passphrase_cb(self.password_cb)
            if self.encrypt_armor_cb.get_active():
                context.set_armor(True)
                ext = ".asc"
            else:
                context.set_armor(False)
                ext = ".gpg"
            keylist = [row[-1].key for row in self.get_selected_keys(
                self.encrypt_for_keys_treeview)]
            if self.encrypt_sign_cb.get_active():
                for row in self.get_selected_keys(
                    self.encrypt_with_keys_treeview):
                    context.signers_add(row[-1].key)
                def encrypt(x,y):
                    self.progress_context.op_encrypt_sign_start(
                        keylist, 1, x, y)
            else:
                def encrypt(x,y):
                    self.progress_context.op_encrypt_start(
                        keylist, 1, x, y)
            self.progress_context = context
            self.process_files_async([(f[0], f[0]+sigext) for f in files],
                                     encrypt, _("Encrypting..."))
                
    def on_decrypt_activate(self, obj):
        "Callback for 'Decrypt' menu item"
        files = self.get_selected_files()
        if not files: return
        
        file_list = []
        for onefile in self.get_selected_files():
            in_name = onefile[0]
            if in_name[-4:] in [".asc", ".gpg", ".pgp"]:
                out_name = in_name[:-4]
            else:
                out_name = in_name + ".txt"
            file_list.append((in_name, out_name))
        self.process_context = Context()
        self.process_files_async(file_list,
                                 self.process_context.op_decrypt_start,
                                 _("Decrypting..."))

    def on_select_all_files_activate(self, obj):
        "Callback for 'Select All' menu item in filemanager"
        self.files_treeview.get_selection().select_all()

    def on_keyring_editor_activate(self, obj):
        "Callback for 'Keyring Editor' menu item"
        self.main_window.show()

    def on_keyring_editor_close_activate(self, obj, event=None):
        "Callback for 'Close' menu item in Keyring Editor"
        if self.filemanager_window.get_property("visible"):
            self.main_window.hide()
            return True
        else:
            self.on_quit_activate(None)    

    def on_filemanager_activate(self, obj):
        "Callback for 'Filemanager' menu item"
        self.on_files_changed(None)
        self.filemanager_window.show()

    def on_filemanager_close_activate(self, obj, event=None):
        "Callback for 'Close' menu item in Filemanager"
        if self.main_window.get_property("visible"):
            self.filemanager_window.hide()
            return True
        else:
            self.on_quit_activate(None)

    def on_about_activate(self, obj):
        "Callback for 'About' menu item"
        self.popup(self.about_dialog)

    def __repr__(self):
        return self.__class__.__name__

    def __getattr__(self, name):
        "Dynamic retrieval of widgets from the glade XML"
        if name.startswith("on_"):
            self.__dict__[name] = lambda x: sys.stderr.write(
                _("Callback %s is not implimented yet\n") % name)
        elif name.startswith("_"):
            return None
        else:
            self.__dict__[name] = self.wtree.get_widget(name)
            return self.__dict__[name]
        
    def __init__(self, path):
        "PyGpa(path) - path is where pygpa.glade file can be found"
        gladefile = os.path.join(path, "pygpa.glade")
        self.wtree = gtk.glade.XML(gladefile, None, gtk.glade.textdomain())
        self.wtree.signal_autoconnect(self)

        self.default_key = None
        self.load_keys()
        self.setup_columns()
        self.setup_default_views()
        self.in_progress = {}
        
        gtk.main()

    def on_quit_activate(self, obj):
        gtk.main_quit()

PyGpa(os.path.dirname(sys.argv[0]))
