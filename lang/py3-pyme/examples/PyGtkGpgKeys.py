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
import time, sys, os
from pyme import callbacks, core, errors
from pyme.core import Data, Context, pubkey_algo_name
from pyme import constants
from pyme.constants import validity
from pyme.constants.keylist import mode

# Thanks to Bernhard Reiter for pointing out the following:
# gpgme_check_version() necessary for initialisation according to 
# gpgme 1.1.6 and this is not done automatically in pyme-0.7.0
print("gpgme version:", core.check_version(None))

# Convert trust constant into a string
trusts = {validity.UNKNOWN: "",
          validity.UNDEFINED: "Undefined",
          validity.NEVER: "Never",
          validity.MARGINAL: "Marginal",
          validity.FULL: "Full",
          validity.ULTIMATE: "Ultimate"}

# Convert seconds into a date
def sec2str(secs):
    if secs > 0:    return time.strftime("%Y-%m-%d", time.gmtime(secs))
    elif secs == 0: return "Unlimited"
    else:           return ""

index = 0
class KeyColumn:
    "Helper class for data columns."
    def __init__(self, name, gtype, vattr=None, tcols=None,
                 func=lambda x:x, view=None):
        """new(name, qtype, vattr, column, ocolumn, func):
        name  - column title
        qtype - gobject type to use in TreeStore for this column
        vattr - column data is visible if method vattr present in the object
        tcols - list of type specific columns to append its name to.
        func  - function converting object data into viewable presentation
        view  - to put or not the column in the view menu"""
        global index
        self.name = name
        self.type = gtype
        self.vattr = vattr
        self.func = func
        self.view = view
        self.index = index
        self.attrs = {}
        if tcols != None: tcols.append(name)
        index += 1

# List column names specific to an object type
key_columns = []                        # names only in key
uid_columns = []                        # names only in uids
sub_columns = []                        # names only in subkeys
sign_columns = []                       # names only in signatures
sub_sign_columns = []                   # names in subkeys and signatures

# Explicite columns
visible_columns = [
    KeyColumn("Secret", gobject.TYPE_BOOLEAN, "subkeys"),
    KeyColumn("Name", gobject.TYPE_STRING, "name", uid_columns,
              lambda x: x.name+(x.comment and " (%s)"%x.comment)),
    KeyColumn("Email", gobject.TYPE_STRING, "email", uid_columns,
              lambda x: x.email),
    KeyColumn("Owner Trust", gobject.TYPE_STRING, "owner_trust", key_columns,
              lambda x: trusts[x.owner_trust], True),
    KeyColumn("Type", gobject.TYPE_STRING, "pubkey_algo", sub_sign_columns,
              lambda x: pubkey_algo_name(x.pubkey_algo)),
    KeyColumn("Length", gobject.TYPE_INT, "length", sub_columns,
              lambda x: x.length),
    KeyColumn("Can Auth", gobject.TYPE_BOOLEAN,"can_authenticate", sub_columns,
              lambda x: x.can_authenticate, False),
    KeyColumn("Can Cert", gobject.TYPE_BOOLEAN, "can_certify", sub_columns,
              lambda x: x.can_certify, False),
    KeyColumn("Can Encr", gobject.TYPE_BOOLEAN, "can_encrypt", sub_columns,
              lambda x: x.can_encrypt, False),
    KeyColumn("Can Sign", gobject.TYPE_BOOLEAN, "can_sign", sub_columns,
              lambda x: x.can_sign, False),
    KeyColumn("Created", gobject.TYPE_STRING, "timestamp", sub_sign_columns,
              lambda x: sec2str(x.timestamp), True),
    KeyColumn("Expires", gobject.TYPE_STRING, "expires", sub_sign_columns,
              lambda x: sec2str(x.expires), True),
    KeyColumn("Id", gobject.TYPE_STRING, "keyid", sub_sign_columns,
              lambda x: x.keyid)
    ]

helper_columns = [
    KeyColumn("Name Invalid", gobject.TYPE_BOOLEAN, None, uid_columns,
              lambda x: x.revoked or x.invalid),
    KeyColumn("Subkey Invalid", gobject.TYPE_BOOLEAN, None, sub_sign_columns,
              lambda x: x.revoked or x.invalid or x.expired),
    KeyColumn("FPR", gobject.TYPE_STRING, None, sub_columns,
              lambda x: x.fpr)
    ]

# Calculate implicite columns - defining visibility of the data in a column.
# In the same loop calculate tuple for rows having only name in them.
name_only = ()
for item in visible_columns:
    vis_item = KeyColumn("Show"+item.name, gobject.TYPE_BOOLEAN)
    helper_columns.append(vis_item)
    item.attrs["visible"] = vis_item.index
    name_only += (vis_item.index, item.name == "Name")

columns = {}
for item in visible_columns + helper_columns:
    columns[item.name] = item

# Use strikethrough to indicate revoked or invalid keys and uids
columns["Name"].attrs["strikethrough"] = columns["Name Invalid"].index
columns["Id"].attrs["strikethrough"] = columns["Subkey Invalid"].index

def pair(name, value):
    "pair(name, value) creates (index, func(value)) tuple based on column name"
    item = columns[name]
    if item.index < len(visible_columns):
        return (item.index, item.func(value), columns["Show"+name].index, True)
    else:
        return (item.index, item.func(value))

class PyGtkGpgKeys:
    "Main class representing PyGtkGpgKeys application"
    def error_message(self, text, parent=None):
        dialog = gtk.MessageDialog(parent or self.mainwin,
                                   gtk.DIALOG_MODAL |
                                   gtk.DIALOG_DESTROY_WITH_PARENT,
                                   gtk.MESSAGE_ERROR,
                                   gtk.BUTTONS_OK,
                                   text)
        dialog.run()
        dialog.destroy()        

    def yesno_message(self, text, parent=None):
        dialog = gtk.MessageDialog(parent or self.mainwin,
                                   gtk.DIALOG_MODAL |
                                   gtk.DIALOG_DESTROY_WITH_PARENT,
                                   gtk.MESSAGE_QUESTION,
                                   gtk.BUTTONS_YES_NO,
                                   text)
        result = dialog.run() == gtk.RESPONSE_YES
        dialog.destroy()
        return result
    
    def load_keys(self, first_time=False):
        if not first_time: self.model.clear()
        secret_keys = {}
        for key in self.context.op_keylist_all(None, 1):
            secret_keys[key.subkeys[0].fpr] = 1
        for key in self.context.op_keylist_all(None, 0):
            self.add_key(key, key.subkeys[0].fpr in secret_keys)
    
    def add_key(self, key, secret):
        "self.add_key(key) - add key to the TreeStore model"
        iter = self.model.append(None)
        # Can delete only the whole key
        param = (iter,) + pair("Secret", secret)
        # Key information is a combination of the key and first uid and subkey
        for col in key_columns: param += pair(col, key)
        for col in uid_columns: param += pair(col, key.uids[0])
        for col in sub_columns: param += pair(col, key.subkeys[0])
        for col in sub_sign_columns: param += pair(col, key.subkeys[0])
        self.model.set(*param)
        if key.uids:
            self.add_signatures(key.uids[0].signatures, iter)
            self.add_uids(key.uids[1:], iter)
        self.add_subkeys(key.subkeys[1:], iter)

    def add_subkeys(self, subkeys, iter):
        "self.add_subkeys(subkey, iter) - add subkey as child to key's iter"
        if not subkeys:
            return
        key_iter = self.model.append(iter)
        self.model.set(key_iter, columns["Name"].index, "Subkeys", *name_only)
        for subkey in subkeys:
            child_iter = self.model.append(key_iter)
            param = (child_iter,)
            for col in sub_columns: param += pair(col, subkey)
            for col in sub_sign_columns: param += pair(col, subkey)
            self.model.set(*param)

    def add_uids(self, uids, iter):
        "self.add_uids(uid, iter) - add uid as a child to key's iter"
        if not uids:
            return
        uid_iter = self.model.append(iter)
        self.model.set(uid_iter,columns["Name"].index,"Other UIDs",*name_only)
        for uid in uids:
            child_iter = self.model.append(uid_iter)
            param = (child_iter,)
            for col in uid_columns: param += pair(col, uid)
            self.model.set(*param)
            self.add_signatures(uid.signatures, child_iter)

    def add_signatures(self, signs, iter):
        "self.add_signatures(sign, iter) - add signature as a child to iter"
        if not signs:
            return
        sign_iter = self.model.append(iter)
        self.model.set(sign_iter,columns["Name"].index,"Signatures",*name_only)
        for sign in signs:
            child_iter = self.model.append(sign_iter)
            param = (child_iter,)
            for col in uid_columns: param += pair(col, sign)
            for col in sign_columns: param += pair(col, sign)
            for col in sub_sign_columns: param += pair(col, sign)
            self.model.set(*param)

    def add_columns(self):
        "Add viewable columns for the data in TreeStore model"
        view_menu = gtk.Menu()
        for item in visible_columns:
            if item.type == gobject.TYPE_BOOLEAN:
                renderer = gtk.CellRendererToggle()
                item.attrs["active"] = item.index
            else:
                renderer = gtk.CellRendererText()
                item.attrs["text"] = item.index
            column = self.treeview.insert_column_with_attributes(
                item.index, item.name, renderer, **item.attrs)
            column.set_sort_column_id(item.index)
            # Create callback for a View menu item
            if item.view != None:
                check = gtk.CheckMenuItem(item.name)
                check.set_active(item.view)
                check.connect("activate",
                              lambda x, y: y.set_visible(x.get_active()),
                              column)
                view_menu.append(check)
                column.set_visible(check.get_active())
                
        view_menu.show_all()
        self.wtree.get_widget("view_menu").set_submenu(view_menu)

    def on_GPGKeysView_button_press_event(self, obj, event):
        if event.button != 3:
            return False

        menu = gtk.Menu()
        for title, callback in [
            ("Reload", self.on_reload_activate),
            (None, None),
            ("Delete", self.on_delete_activate),
            ("Export (txt)", self.on_export_keys_text_activate),
            ("Export (bin)", self.on_export_keys_activate)
            ]:
            if title:
                item = gtk.MenuItem(title)
                item.connect("activate", callback)
            else:
                item = gtk.SeparatorMenuItem()
            menu.append(item)
        menu.show_all()
        
        menu.popup(None, None, None, event.button, event.time)
        return True

    def editor_func(self, status, args, val_dict):
        state = val_dict["state"]
        prompt = "%s %s" % (state, args)
        if prompt in val_dict:
            val_dict["state"] = val_dict[prompt][0]
            return val_dict[prompt][1]
        elif args:
            sys.stderr.write("Unexpected prompt in editor_func: %s\n" % prompt)
            raise EOFError()
        return ""

    def change_key_trust(self, key, new_trust):
        val_dict = {
            "state": "start",
            "start keyedit.prompt": ("trust", "trust"),
            "trust edit_ownertrust.value": ("prompt", "%d" % new_trust),
            "prompt edit_ownertrust.set_ultimate.okay": ("prompt", "Y"),
            "prompt keyedit.prompt": ("finish", "quit")
            }
        out = Data()
        self.context.op_edit(key, self.editor_func, val_dict, out)

    def on_change_trust(self, new_trust):
        selection = self.treeview.get_selection()
        if selection.count_selected_rows() <= 0:
            return
        
        key_list = []
        selection.selected_foreach(self.collect_keys, key_list)

        message = "Change trust to %s on the following keys?\n" % \
                  trusts[new_trust]
        for key, row in key_list:
            message += "\n%s\t" % key.subkeys[0].keyid
            if key.uids: message += key.uids[0].uid
            else:        message += "<undefined>"                
        if self.yesno_message(message):
            for key, row in key_list:
                if key.owner_trust != new_trust:
                    self.change_key_trust(key, new_trust)
                    row[columns["Owner Trust"].index] = trusts[new_trust]

    def on_undefined_trust_activate(self, obj):
        self.on_change_trust(1)

    def on_never_trust_activate(self, obj):
        self.on_change_trust(2)

    def on_marginal_trust_activate(self, obj):
        self.on_change_trust(3)

    def on_full_trust_activate(self, obj):
        self.on_change_trust(4)

    def on_ultimate_trust_activate(self, obj):
        self.on_change_trust(5)

    def collect_keys(self, model, path, iter, key_list):
        row = model[path[:1]]
        keyid = row[columns["FPR"].index]
        key = self.context.get_key(keyid, 0)
        key_list.append((key, row))

    def export_keys(self):
        selection = self.treeview.get_selection()
        if selection.count_selected_rows() <= 0:
            return
        
        export_file = None
        dialog = gtk.FileChooserDialog("Export Keys (Public only) into a File",
                                       self.mainwin,
                                       gtk.FILE_CHOOSER_ACTION_SAVE,
                                       (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                        gtk.STOCK_OK, gtk.RESPONSE_OK))
        while dialog.run() == gtk.RESPONSE_OK:
            filename = dialog.get_filename()
            if os.path.exists(filename):
                if os.path.isdir(filename):
                    self.error_message("%s is a directory!" % filename,
                                       dialog)
                    continue
                elif not self.yesno_message("%s exists. Override?" % filename,
                                            dialog):
                    continue

            # FIXME. Verify that file can be written to
            export_file = open(filename, "wb")
            break
        dialog.destroy()
        if export_file == None:
            return

        key_list = []
        selection.selected_foreach(self.collect_keys, key_list)
        expkeys = Data()
        for key, row in key_list:
            self.context.op_export(key.subkeys[0].fpr, 0, expkeys)
        expkeys.seek(0,0)
        export_file.write(expkeys.read())
        export_file.close()
            
    def on_export_keys_activate(self, obj):
        self.context.set_armor(0)
        self.export_keys()

    def on_export_keys_text_activate(self, obj):
        self.context.set_armor(1)
        self.export_keys()

    def on_import_keys_activate(self, obj):
        import_file = None
        dialog = gtk.FileChooserDialog("Import Keys from a File",
                                       self.mainwin,
                                       gtk.FILE_CHOOSER_ACTION_OPEN,
                                       (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                        gtk.STOCK_OK, gtk.RESPONSE_OK))
        while dialog.run() == gtk.RESPONSE_OK:
            filename = dialog.get_filename()
            if os.path.exists(filename):
                if os.path.isdir(filename):
                    self.error_message("%s is a directory!" % filename,
                                       dialog)
                else:
                    # FIXME. Verify that file can be open.
                    import_file = filename
                    break
            else:
                self.error_message("%s does not exist." % filename,
                                   dialog)
        dialog.destroy()
        if import_file == None:
            return

        impkeys = Data(file=import_file)
        status = self.context.op_import(impkeys)
        if status:
            self.error_message("Import return an error message %d" % status)
        result = self.context.op_import_result()
        if result.considered == 0:
            self.error_message("There's no keys in the file.")
        # FIXME. Instead of rereading everything we could find out what's new
        # from the result based on the ORed value of impkey:
        # constants.import.NEW    - The key was new.
        # constants.import.UID    - The key contained new user IDs.
        # constants.import.SIG    - The key contained new signatures.
        # constants.import.SUBKEY - The key contained new sub keys.
        # constants.import.SECRET - The key contained a secret key.
        # It would be nice to highlight new things as well.
        self.load_keys()
        #if result:
        #    impkey = result.imports
        #    while impkey:
        #        if impkey.status & constants.import.NEW:
        #            self.add_key(self.context.get_key(impkey.fpr, 0))
        #        impkey = impkey.next

    def on_delete_activate(self, obj):
        "self.on_delete_activate(obj) - callback for key deletion request"
        selection = self.treeview.get_selection()
        if selection.count_selected_rows() > 0:
            key_list = []
            selection.selected_foreach(self.collect_keys, key_list)
            
            message = "Delete selected keys?\n"
            for key, row in key_list:
                message += "\n%s\t" % key.subkeys[0].keyid
                if key.uids: message += key.uids[0].uid
                else:        message += "<undefined>"                
            if self.yesno_message(message):
                for key, row in key_list:
                    self.context.op_delete(key, 1)
                    row.model.remove(row.iter)

    def get_widget_values(self, widgets):
        "Create an array of values from widgets' getter methods"
        return [getattr(self.wtree.get_widget(w),"get_"+f)() for w,f in widgets]

    def set_widget_values(self, widgets, values):
        "Set values using widgets' setter methods"
        for (w,f), v in zip(widgets, values):
            # ComboBox.set_active_iter(None) does not reset active. Fixing.
            if f == "active_iter" and v == None:
                f, v = "active", -1
            getattr(self.wtree.get_widget(w), "set_"+f)(v)

    def key_type_changed(self, which):
        """self.key_type_changed([\"key\"|\"subkey\"]) - helper function to
        adjust allowed key length based on the Algorithm selected"""
        (key_type,) = self.get_widget_values([(which+"_type", "active_iter")])
        if key_type:
            key_type = self.wtree.get_widget(which+"_type").get_model(
                ).get_value(key_type,0)
            length_widget = self.wtree.get_widget(which+"_length")
            if key_type == "DSA":
                length_widget.set_range(1024, 1024)
                length_widget.set_value(1024)
            elif key_type == "RSA" or key_type == "ELG-E":
                length_widget.set_range(1024, 4096)

    def on_key_type_changed(self, obj):
        self.key_type_changed("key")

    def on_subkey_type_changed(self, obj):
        self.key_type_changed("subkey")

    def on_expire_calendar_day_selected(self, obj):
        "Callback for selecting a day on the calendar"
        (year, month, day)=self.wtree.get_widget("expire_calendar").get_date()
        expander = self.wtree.get_widget("expire_date")
        # Past dates means no expiration date
        if time.localtime() < (year, month+1, day):
            expander.set_label("%04d-%02d-%02d" % (year, month+1, day))
        else:
            expander.set_label("Unlimited")
        expander.set_expanded(False)

    def on_generate_activate(self, obj):
        "Callback to generate new key"
        
        # Set of (widget, common suffix of getter/setter function) tuples
        # from the GenerateDialog prompt for new key properties.
        widgets = [
            ("key_type", "active_iter"),
            ("key_length", "value"),
            ("key_encrypt", "active"),
            ("key_sign", "active"),
            ("subkey_type", "active_iter"),
            ("subkey_length", "value"),
            ("subkey_encrypt", "active"),
            ("subkey_sign", "active"),
            ("name_real", "text"),
            ("name_comment", "text"),
            ("name_email", "text"),
            ("expire_date", "label"),
            ("passphrase", "text"),
            ("passphrase_repeat", "text")
            ]

        saved_values = self.get_widget_values(widgets)
        result = None
        dialog = self.wtree.get_widget("GenerateDialog")
        if dialog.run() == gtk.RESPONSE_OK:
            (key_type, key_length, key_encrypt, key_sign,
             subkey_type, subkey_length, subkey_encrypt, subkey_sign,
             name_real, name_comment, name_email, expire_date,
             passphrase, passphrase2) = self.get_widget_values(widgets)
            if key_type and passphrase == passphrase2:
                key_type = self.wtree.get_widget("key_type").get_model(
                    ).get_value(key_type,0)
                result = "<GnupgKeyParms format=\"internal\">\n"
                result += "Key-Type: %s\n" % key_type
                result += "Key-Length: %d\n" % int(key_length)
                if key_encrypt or key_sign:
                    result += "Key-Usage:" + \
                              ((key_encrypt and " encrypt") or "") + \
                              ((key_sign and " sign") or "") + "\n"
                if subkey_type:
                    subkey_type=self.wtree.get_widget("subkey_type").get_model(
                        ).get_value(subkey_type,0)
                    result += "Subkey-Type: %s\n" % subkey_type
                    result += "Subkey-Length: %d\n" % int(subkey_length)
                    if subkey_encrypt or subkey_sign:
                        result += "Subkey-Usage:" + \
                                  ((subkey_encrypt and " encrypt") or "") + \
                                  ((subkey_sign and " sign") or "") + "\n"
                if name_real:
                    result += "Name-Real: %s\n" % name_real
                if name_comment:
                    result += "Name-Comment: %s\n" % name_comment
                if name_email:
                    result += "Name-Email: %s\n" % name_email
                if passphrase:
                    result += "Passphrase: %s\n" % passphrase
                if expire_date != "Unlimited":
                    result += "Expire-Date: %s\n" % expire_date
                else:
                    result += "Expire-Date: 0\n"
                result += "</GnupgKeyParms>\n"
            else:
                if not key_type:
                    message = "Type of the primary key is not specified."
                elif passphrase != passphrase2:
                    message = "Passphrases do not match."
                else:
                    message = "Unknown error."
                self.error_message(message, dialog)
        else:
            self.set_widget_values(widgets, saved_values)

        dialog.hide()
        if result:
            # Setup and show progress Dialog
            self.progress = ""
            self.progress_entry = self.wtree.get_widget(
                "progress_entry").get_buffer()
            self.progress_entry.set_text("")
            gobject.timeout_add(500, self.update_progress)
            self.wtree.get_widget("GenerateProgress").show_all()
            # Start asynchronous key generation
            self.context.op_genkey_start(result, None, None)

    def gen_progress(self, what=None, type=None, current=None,
                     total=None, hook=None):
        "Gpg's progress_cb"
        if self.progress != None:
            self.progress += "%c" % type
        else:
            sys.stderr.write("%c" % type)

    def update_progress(self):
        "Timeout callback to yeild to gpg and update progress Dialog view"
        status = self.context.wait(False)
        if status == None:
            self.progress_entry.set_text(self.progress)
            return True
        elif status == 0:
            fpr = self.context.op_genkey_result().fpr
            self.add_key(self.context.get_key(fpr, 0), True)
        self.wtree.get_widget("GenerateProgress").hide()
        self.progress = None

        if status:
            self.error_message("Got an error during key generation:\n%s" %
                               errors.GPGMEError(status).getstring())

        # Let callback to be removed.
        return False

    def on_generating_close_clicked(self, obj):
        # Request cancelation of the outstanding asynchronous call
        self.context.cancel()

    def get_password(self, hint, desc, hook):
        "Gpg's password_cb"
        dialog = self.wtree.get_widget("PasswordDialog")
        label = self.wtree.get_widget("pwd_prompt")
        entry = self.wtree.get_widget("password")
        label.set_text("Please supply %s's password%s:" %
                       (hint, (hook and (' '+hook)) or ''))
        if dialog.run() == gtk.RESPONSE_OK:
            result = entry.get_text()
        else:
            result = ""
        entry.set_text("")
        dialog.hide()
        return result

    def on_reload_activate(self, obj):
        self.load_keys()

    def on_about_activate(self, obj):
        about = self.wtree.get_widget("AboutDialog")
        about.run()
        about.hide()

    def __init__(self, path):
        "new(path) path - location of the glade file"
        gladefile = os.path.join(path, "PyGtkGpgKeys.glade")
        self.wtree = gtk.glade.XML(gladefile)
        self.wtree.signal_autoconnect(self)

        self.mainwin = self.wtree.get_widget("GPGAdminWindow")
        self.treeview = self.wtree.get_widget("GPGKeysView")

        self.model = gtk.TreeStore(*[x.type for x in visible_columns +
                                     helper_columns])        

        self.context = Context()
        self.context.set_passphrase_cb(self.get_password, "")
        self.progress = None
        self.context.set_progress_cb(self.gen_progress, None)
        # Use mode.SIGS to include signatures in the list.
        self.context.set_keylist_mode(mode.SIGS)
        self.load_keys(True)

        self.treeview.set_model(self.model)
        self.treeview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        self.add_columns()

        gtk.main()

    def on_Exit(self, obj):
        gtk.main_quit()

try:
    # Glade file is expected to be in the same location as this script
    PyGtkGpgKeys(os.path.dirname(sys.argv[0]))
except IOError as message:
    print("%s:%s" %(sys.argv[0], message))
