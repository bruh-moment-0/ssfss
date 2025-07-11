from tkinter import Tk, Frame, scrolledtext, simpledialog, messagebox, filedialog, Label, Button, Entry, Checkbutton, Spinbox, StringVar, BooleanVar, IntVar, WORD, CHAR, END, INSERT, DISABLED, NORMAL
from tkinter.ttk import Combobox
from datetime import datetime, timedelta, timezone
from argon2.low_level import hash_secret_raw, Type
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from pathlib import Path
import threading
import secrets
import base64
import string
import time
import zlib
import json
import os

VERSION = 3.1
BASEDIR = os.path.dirname(os.path.abspath(__file__))
SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
KDF_ITERATIONS = 100_000

def keygen(length_bytes=32):
    key_bytes = secrets.token_bytes(length_bytes)
    return base64.b64encode(key_bytes).decode('utf-8')

def keydecode(key_b64):
    return base64.b64decode(key_b64)

def _to_bytes(s):
    return s.encode('utf-8') if isinstance(s, str) else s

def encryptAESGCM(data, password):
    salt = get_random_bytes(SALT_LENGTH)
    nonce = get_random_bytes(NONCE_LENGTH)
    key = hash_secret_raw(
        secret=_to_bytes(password),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=KEY_LENGTH,
        type=Type.ID
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    blob = ciphertext + tag
    return base64.b64encode(blob).decode(), base64.b64encode(salt).decode(), base64.b64encode(nonce).decode()

def decryptAESGCM(blob_b64, password, salt_b64, nonce_b64):
    blob = base64.b64decode(blob_b64)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    key = hash_secret_raw(
        secret=_to_bytes(password),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=KEY_LENGTH,
        type=Type.ID
    )
    tag = blob[-16:]
    ct = blob[:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode('utf-8')

def gettime():
    tz = timezone(timedelta(hours=3))
    timestamp = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S GMT+3')
    return timestamp

def timeappend():
    appendscroll(textscroll, gettime(), False, False)

class PasswordDialog(simpledialog.Dialog):
    def body(self, master):
        Label(master, text="Password:").grid(row=0, column=0)
        self.password_var = StringVar()
        self.show_password_var = BooleanVar(value=False)
        self.password_entry = Entry(master, textvariable=self.password_var, width=48, show="*")
        self.password_entry.grid(row=0, column=1, columnspan=2)
        self.generate_button = Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=1, column=0)
        Label(master, text="Password Length (8-512):").grid(row=1, column=1)
        self.length_var = IntVar(value=32)
        self.length_spinbox = Spinbox(master, from_=8, to=512, textvariable=self.length_var, width=5)
        self.length_spinbox.grid(row=1, column=2)
        self.show_checkbox = Checkbutton(master, text="Show Password", variable=self.show_password_var, command=self.toggle_show_password)
        self.show_checkbox.grid(row=2, column=0, columnspan=3)
        return self.password_entry
    def toggle_show_password(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    def generate_password(self):
        length = self.length_var.get()
        password = generaterandompassword(length)
        self.password_var.set(password)
    def apply(self):
        self.result = self.password_var.get()

def generaterandompassword(length: int = 32) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join([secrets.choice(characters) for _ in range(length)])
    return password

def updateui():
    if wrapselector.get() == "WORD":
        textscroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=WORD)
        filescroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=WORD)
        folderscroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=WORD)
        infoscroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=WORD)
    if wrapselector.get() == "CHAR":
        textscroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=CHAR)
        filescroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=CHAR)
        folderscroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=CHAR)
        infoscroll.config(font=("Consolas", fontsize.get()), width=width.get(), height=height.get(), wrap=CHAR)

def showframe(frame):
    already_visible = frame.winfo_ismapped()
    textframe.grid_forget()
    fileframe.grid_forget()
    folderframe.grid_forget()
    infoframe.grid_forget()
    if not already_visible:
        frame.grid(row=6, column=0, columnspan=5, sticky="nsew")

def writeentry(entry, data, disable):
    entry.config(state=NORMAL)
    entry.delete(0, END)
    entry.insert(END, data)
    if disable:
        entry.config(state=DISABLED)

def writescroll(scroll, data, disable):
    scroll.config(state=NORMAL)
    scroll.delete(1.0, END)
    scroll.insert(END, data)
    if disable:
        scroll.config(state=DISABLED)

def readscroll(scroll):
    return scroll.get("1.0", END).strip()

def appendscroll(scroll, data, disable, newline):
    scroll.config(state=NORMAL)
    cursorpos = scroll.index(INSERT)
    if newline:
        data = "\n" + data
    scroll.insert(cursorpos, data)
    if disable:
        scroll.config(state=DISABLED)

def loop():
    data = readscroll(textscroll)
    length = len(data.encode("utf-8"))
    lenent.delete(0, END)
    lenent.insert(0, f"{length}")
    root.after(100, loop)

def writejson(filename, content, mode='w', indent=4):
    with open(filename, mode) as file:
        json.dump(content, file, indent=indent)

def readjson(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data

def writebin64(filename, content):
    with open(filename, 'wb') as file:
        file.write(base64.b64decode(content))

def readbin64(filename):
    with open(filename, 'rb') as file:
        data = base64.b64encode(file.read()).decode('utf-8')
    return data

def read(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def write(file_path, data):
    with open(file_path, 'w') as file:
        file.write(data)

def text2byte(text):
    byte = text.encode('utf-8')
    return byte

def byte2text(byte_text):
    text = byte_text.decode('utf-8')
    return text

def byte2base64(byte_data):
    base64_text = base64.b64encode(byte_data).decode('utf-8')
    return base64_text

def base642byte(base64_text):
    byte_data = base64.b64decode(base64_text.encode('utf-8'))
    return byte_data

def text2compressed(text):
    byte = text2byte(text)
    compressed = zlib.compress(byte)
    return compressed

def compressed2text(compressed):
    byte = zlib.decompress(compressed)
    text = byte2text(byte)
    return text

def skeycreate():
    filepath = filedialog.asksaveasfilename(
        title="create .skey",
        initialdir=BASEDIR,
        initialfile=f"key_{int(time.time())}.skey",
        defaultextension=".skey",
        filetypes=[("secure key file", "*.skey")]
    )
    if not filepath:
        messagebox.showerror("error", "no path selected for creating .skey")
        return
    messagebox.showwarning("warning", "you will now enter a 'master key' for this .skey file. without your master key, you will not be able to encrypt/decrypt any files using this .skey so it is advised for the user to not lose/forget it. never share your master key, if somebody has it create a new .skey and remove all your encrypted files immediately!")
    passworddialog = PasswordDialog(root)
    password = passworddialog.result
    if not password:
        messagebox.showerror("error", "no password")
        return
    blob, salt, iv = encryptAESGCM(keygen(), password)
    data = {
        "enc": {
            "blob": blob,
            "salt": salt,
            "iv": iv
        },
        "app": "ssfss",
        "type": "skey",
        "ver": VERSION,
        "stamp": time.time()
    }
    data2 = json.dumps(data)
    data3 = text2compressed(data2)
    data4 = byte2base64(data3)
    write(filepath, data4)
    size = os.path.getsize(filepath)
    messagebox.showinfo("created .skey", f"created .skey: saved {size} bytes to {filepath}")

def skeyselect():
    filepath = filedialog.askopenfilename(
        title="select .skey",
        initialdir=BASEDIR,
        defaultextension=".skey",
        filetypes=[("secure key file", "*.skey")]
    )
    if not filepath:
        messagebox.showerror("error", "no path selected for selecting .skey")
        return
    data4 = read(filepath)
    data3 = base642byte(data4)
    data2 = compressed2text(data3)
    data = json.loads(data2)
    blob = data["enc"]["blob"]
    salt = data["enc"]["salt"]
    iv = data["enc"]["iv"]
    app = data["app"]
    type = data["type"]
    ver = data["ver"]
    stamp = data["stamp"]
    if app != "ssfss":
        messagebox.showerror("error", "not a valid .skey file: .skey file is corrupted. app check failed")
        return
    if type != "skey":
        messagebox.showerror("error", "not a valid .skey file: .skey file is corrupted. type check failed")
        return
    if ver != VERSION:
        messagebox.showwarning("warning", f"version mismatch! current: {VERSION}, imported .skey: {ver} this migth cause issues")
    keypath.set(filepath)
    size = len(data2)
    dayold = (time.time()-stamp)//(60*60*24)
    messagebox.showinfo("selected .skey", f"selected .skey: loaded {size} bytes from {filepath}, .skey is {dayold} days old")

def skeypassword():
    filepath = keypath.get()
    if not filepath or filepath == ".skey path":
        messagebox.showerror("error", "no path selected for selecting .skey, please select a path before entering password")
        return
    messagebox.showinfo("info", f"please enter your master key used to create this .skey file ({filepath}) on the next screen.")
    passworddialog = PasswordDialog(root)
    password = passworddialog.result
    if not password:
        messagebox.showerror("error", "no password")
        return
    masterkeyvar.set(password)
    writeentry(passwordent, "********", True)
    messagebox.showinfo("entered master key", "enter master key successfully")

def skeyforget():
    result = messagebox.askyesno("warning", "warning! if you proceed you will need to select your .skey file and enter your master key used to create that .skey file")
    if not result:
        messagebox.showinfo("canceled", "user canceled the operation to forget .skey and master key")
        return
    filepath = keypath.get()
    if (not filepath or filepath == ".skey path") and (not masterkeyvar.get()):
        messagebox.showerror("error", "no path or master key to forget")
        return
    masterkeyvar.set("")
    keypath.set(".skey path")
    writeentry(passwordent, "press 'enter master key'", True)
    messagebox.showinfo("success", "the .skey and/or master key values are forgotten")

def teenc():
    skeypath = keypath.get()
    if (not skeypath or skeypath == ".skey path"):
        messagebox.showerror("error", "no .skey is selected, please select a path")
        return
    masterkey = masterkeyvar.get()
    if (not masterkey):
        messagebox.showerror("error", "no master key selected")
        return
    outfilepath = filedialog.asksaveasfilename(
        title="save a .sstf file",
        initialdir=BASEDIR,
        initialfile=f"text_{int(time.time())}.sstf",
        defaultextension=".sstf",
        filetypes=[("super secure text file", "*.sstf")]
    )
    if not outfilepath:
        messagebox.showerror("error", "no .sstf path selected")
        return
    data4SKEY = read(skeypath)
    data3SKEY = base642byte(data4SKEY)
    data2SKEY = compressed2text(data3SKEY)
    dataSKEY = json.loads(data2SKEY)
    blobSKEY = dataSKEY["enc"]["blob"]
    saltSKEY = dataSKEY["enc"]["salt"]
    ivSKEY = dataSKEY["enc"]["iv"]
    password = keydecode(decryptAESGCM(blobSKEY, masterkey, saltSKEY, ivSKEY))
    blob, salt, iv = encryptAESGCM(readscroll(textscroll), password)
    data = {
        "enc": {
            "blob": blob,
            "salt": salt,
            "iv": iv
        },
        "key": os.path.basename(skeypath),
        "app": "ssfss",
        "type": "sstf",
        "ver": VERSION,
        "stamp": time.time()
    }
    data2 = json.dumps(data)
    data3 = text2compressed(data2)
    data4 = byte2base64(data3)
    write(outfilepath, data4)
    size = os.path.getsize(outfilepath)
    messagebox.showinfo("encrypted as .sstf", f"encrypted as .sstf: saved {size} bytes to {outfilepath}, .skey is from {skeypath}")

def tedec():
    skeypath = keypath.get()
    if (not skeypath or skeypath == ".skey path"):
        messagebox.showerror("error", "no .skey is selected, please select a path")
        return
    masterkey = masterkeyvar.get()
    if (not masterkey):
        messagebox.showerror("error", "no master key selected")
        return
    infilepath = filedialog.askopenfilename(
        title="load a .sstf file",
        initialdir=BASEDIR,
        defaultextension=".sstf",
        filetypes=[("super secure text file", "*.sstf")]
    )
    if not infilepath:
        messagebox.showerror("error", "no .sstf path selected")
        return
    data4 = read(infilepath)
    data3 = base642byte(data4)
    data2 = compressed2text(data3)
    data = json.loads(data2)
    blob = data["enc"]["blob"]
    salt = data["enc"]["salt"]
    iv = data["enc"]["iv"]
    skeypath_original = data["key"]
    app = data["app"]
    type = data["type"]
    ver = data["ver"]
    stamp = data["stamp"]
    if skeypath_original != os.path.basename(skeypath):
        messagebox.showwarning("warning", "the .sstf files .skey used to encrypt it does not match the name of the given .skey by the user. if they are not the same file, decryption migth fail!")
    if app != "ssfss":
        messagebox.showerror("error", "not a valid .sstf file: .sstf file is corrupted. app check failed")
        return
    if type != "sstf":
        messagebox.showerror("error", "not a valid .sstf file: .sstf file is corrupted. type check failed")
        return
    if ver != VERSION:
        messagebox.showwarning("warning", f"version mismatch! current: {VERSION}, imported .sstf: {ver} this migth cause issues")
    data4SKEY = read(skeypath)
    data3SKEY = base642byte(data4SKEY)
    data2SKEY = compressed2text(data3SKEY)
    dataSKEY = json.loads(data2SKEY)
    blobSKEY = dataSKEY["enc"]["blob"]
    saltSKEY = dataSKEY["enc"]["salt"]
    ivSKEY = dataSKEY["enc"]["iv"]
    password = keydecode(decryptAESGCM(blobSKEY, masterkey, saltSKEY, ivSKEY))
    decrypted = decryptAESGCM(blob, password, salt, iv)
    writescroll(textscroll, decrypted, False)
    size = len(decrypted)
    dayold = (time.time()-stamp)//(60*60*24)
    messagebox.showinfo("decrypted .sstf", f"decrypted from .sstf: loaded {size} bytes from {infilepath}, .skey is from {skeypath}. data is {dayold} days old")

def fienc():
    welcome = (
        "=== ssfss file encryption utility for .ss1f files ===\n"
        f"version : {VERSION}\n"
        f"date and time : {gettime()}"
    )
    writescroll(filescroll, welcome, True)
    skeypath = keypath.get()
    if (not skeypath or skeypath == ".skey path"):
        messagebox.showerror("error", "no .skey is selected, please select a path")
        appendscroll(filescroll, "error: no .skey is selected, please select a path", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    masterkey = masterkeyvar.get()
    if (not masterkey):
        messagebox.showerror("error", "no master key selected")
        appendscroll(filescroll, "error: no master key selected", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    infilepath = filedialog.askopenfilename(
        title="load a file",
        initialdir=BASEDIR,
        filetypes=[("all files", "*.*")]
    )
    if not infilepath:
        messagebox.showerror("error", "no path selected for the file to encrypt")
        appendscroll(filescroll, "error: no path selected for the file to encrypt", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    outfilepath = filedialog.asksaveasfilename(
        title="save a .ss1f file",
        initialdir=BASEDIR,
        initialfile=f"file_{int(time.time())}.ss1f",
        defaultextension=".ss1f",
        filetypes=[("super secure singular file", "*.ss1f")]
    )
    if not outfilepath:
        messagebox.showerror("error", "no .ss1f path selected")
        appendscroll(filescroll, "error: no .ss1f path selected", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    appendscroll(filescroll, "reading and loading .skey ...", True, True)
    data4SKEY = read(skeypath)
    data3SKEY = base642byte(data4SKEY)
    data2SKEY = compressed2text(data3SKEY)
    dataSKEY = json.loads(data2SKEY)
    blobSKEY = dataSKEY["enc"]["blob"]
    saltSKEY = dataSKEY["enc"]["salt"]
    ivSKEY = dataSKEY["enc"]["iv"]
    appendscroll(filescroll, "decrypting .skey ...", True, True)
    password = keydecode(decryptAESGCM(blobSKEY, masterkey, saltSKEY, ivSKEY))
    indata = readbin64(infilepath)
    appendscroll(filescroll, f"encrypting {infilepath} ...", True, True)
    blob, salt, iv = encryptAESGCM(indata, password)
    blobNAME, saltNAME, ivNAME = encryptAESGCM(os.path.basename(infilepath), password)
    appendscroll(filescroll, f"saving as {outfilepath} ...", True, True)
    data = {
        "enc": {
            "blob": blob,
            "salt": salt,
            "iv": iv
        },
        "name": {
            "blob": blobNAME,
            "salt": saltNAME,
            "iv": ivNAME
        },
        "key": os.path.basename(skeypath),
        "app": "ssfss",
        "type": "ss1f",
        "ver": VERSION,
        "stamp": time.time()
    }
    data2 = json.dumps(data)
    data3 = text2compressed(data2)
    data4 = byte2base64(data3)
    write(outfilepath, data4)
    size = os.path.getsize(outfilepath)
    messagebox.showinfo("encrypted as .ss1f", f"encrypted as .ss1f: saved {size} bytes to {outfilepath}, .skey is from {skeypath}")
    appendscroll(filescroll, f"success: encrypted as .ss1f: saved {size} bytes to {outfilepath}, .skey is from {skeypath}", True, True)
    appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)

def fidec():
    welcome = (
        "=== ssfss file decryption utility for .ss1f files ===\n"
        f"version : {VERSION}\n"
        f"date and time : {gettime()}"
    )
    writescroll(filescroll, welcome, True)
    skeypath = keypath.get()
    if (not skeypath or skeypath == ".skey path"):
        messagebox.showerror("error", "no .skey is selected, please select a path")
        appendscroll(filescroll, "error: no .skey is selected, please select a path", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    masterkey = masterkeyvar.get()
    if (not masterkey):
        messagebox.showerror("error", "no master key selected")
        appendscroll(filescroll, "error: no master key selected", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    infilepath = filedialog.askopenfilename(
        title="load a .ss1f file",
        initialdir=BASEDIR,
        filetypes=[("super secure singular file", "*.ss1f")]
    )
    if not infilepath:
        messagebox.showerror("error", "no path selected for decrypting the .ss1f")
        appendscroll(filescroll, "error: no path selected for decrypting the .ss1f", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    appendscroll(filescroll, "reading and loading .ss1f ...", True, True)
    data4 = read(infilepath)
    data3 = base642byte(data4)
    data2 = compressed2text(data3)
    data = json.loads(data2)
    blob = data["enc"]["blob"]
    salt = data["enc"]["salt"]
    iv = data["enc"]["iv"]
    skeypath_original = data["key"]
    app = data["app"]
    type = data["type"]
    ver = data["ver"]
    stamp = data["stamp"]
    if skeypath_original != os.path.basename(skeypath):
        messagebox.showwarning("warning", "the .ss1f files .skey used to encrypt it does not match the name of the given .skey by the user. if they are not the same file, decryption migth fail!")
        appendscroll(filescroll, "warning: the .ss1f files .skey used to encrypt it does not match the name of the given .skey by the user. if they are not the same file, decryption migth fail!", True, True)
    if app != "ssfss":
        messagebox.showerror("error", "not a valid .ss1f file: .ss1f file is corrupted. app check failed")
        appendscroll(filescroll, "error: not a valid .ss1f file: .ss1f file is corrupted. app check failed", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    if type != "ss1f":
        messagebox.showerror("error", "not a valid .ss1f file: .ss1f file is corrupted. type check failed")
        appendscroll(filescroll, "error: not a valid .ss1f file: .ss1f file is corrupted. type check failed", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    if ver != VERSION:
        messagebox.showwarning("warning", f"version mismatch! current: {VERSION}, imported .sstf: {ver} this migth cause issues")
        appendscroll(filescroll, f"warning: version mismatch! current: {VERSION}, imported .sstf: {ver} this migth cause issues", True, True)
    appendscroll(filescroll, "reading and loading .skey ...", True, True)
    data4SKEY = read(skeypath)
    data3SKEY = base642byte(data4SKEY)
    data2SKEY = compressed2text(data3SKEY)
    dataSKEY = json.loads(data2SKEY)
    blobSKEY = dataSKEY["enc"]["blob"]
    saltSKEY = dataSKEY["enc"]["salt"]
    ivSKEY = dataSKEY["enc"]["iv"]
    appendscroll(filescroll, "decrypting .skey ...", True, True)
    password = keydecode(decryptAESGCM(blobSKEY, masterkey, saltSKEY, ivSKEY))
    appendscroll(filescroll, f"decrypting {infilepath} ...", True, True)
    decrypted = decryptAESGCM(blob, password, salt, iv)
    blobNAME = data["name"]["blob"]
    saltNAME = data["name"]["salt"]
    ivNAME = data["name"]["iv"]
    name_original = decryptAESGCM(blobNAME, password, saltNAME, ivNAME)
    ext_original = Path(name_original).suffix
    ext_original_dotless = Path(name_original).suffix[1:]
    outfilepath = filedialog.asksaveasfilename(
        title="save as a file",
        initialdir=BASEDIR,
        initialfile=name_original,
        defaultextension=ext_original,
        filetypes=[(f"{ext_original_dotless} file", f"*.{ext_original_dotless}"), ("all files", "*.*")]
    )
    if not outfilepath:
        messagebox.showerror("error", "no path selected for the decrypted file")
        appendscroll(filescroll, "error: no path selected for the decrypted file", True, True)
        appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)
        return
    appendscroll(filescroll, f"saving as {outfilepath} ...", True, True)
    writebin64(outfilepath, decrypted)
    size = os.path.getsize(outfilepath)
    messagebox.showinfo("decrypted from .ss1f", f"decrypted from .ss1f: saved {size} bytes to {outfilepath}, .skey is from {skeypath}")
    appendscroll(filescroll, f"decrypted from .ss1f: saved {size} bytes to {outfilepath}, .skey is from {skeypath}", True, True)
    appendscroll(filescroll, "="*len(welcome.split("\n")[0]), True, True)

def _human(n):
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    step = 0
    x = float(n)
    while x >= 1024 and step < len(units) - 1:
        x /= 1024
        step += 1
    s = f"{x:.2f}".rstrip('0').rstrip('.')
    return f"{s} {units[step]}"

def foenc():
    welcome = (
        "=== ssfss folder encryption utility for .ss2f files ===\n"
        f"version : {VERSION}\n"
        f"date and time : {gettime()}"
    )
    writescroll(folderscroll, welcome, True)
    skeypath = keypath.get()
    if not skeypath or skeypath == ".skey path":
        messagebox.showerror("error", "no .skey is selected")
        appendscroll(folderscroll, "error: no .skey is selected", True, True)
        return
    masterkey = masterkeyvar.get()
    if not masterkey:
        messagebox.showerror("error", "no master key selected")
        appendscroll(folderscroll, "error: no master key selected", True, True)
        return
    infolderpath = filedialog.askdirectory(
        title="select folder",
        initialdir=BASEDIR
    )
    if not infolderpath:
        messagebox.showerror("error", "no folder selected")
        appendscroll(folderscroll, "error: no folder selected", True, True)
        return
    outfilepath = filedialog.asksaveasfilename(
        title="save .ss2f",
        initialdir=BASEDIR,
        initialfile=f"folder_{int(time.time())}.ss2f",
        defaultextension=".ss2f",
        filetypes=[("super secure folder file", "*.ss2f")]
    )
    if not outfilepath:
        messagebox.showerror("error", "no output path selected")
        appendscroll(folderscroll, "error: no output path selected", True, True)
        return
    appendscroll(folderscroll, f"selected folder: {infolderpath}", True, True)
    appendscroll(folderscroll, "reading and decrypting .skey ...", True, True)
    dataSKEY = json.loads(compressed2text(base642byte(read(skeypath))))
    password = keydecode(decryptAESGCM(dataSKEY["enc"]["blob"], masterkey, dataSKEY["enc"]["salt"], dataSKEY["enc"]["iv"]))
    encrypted_tree = {}
    for rootdir, _, files in os.walk(infolderpath):
        for fname in files:
            total_path = os.path.join(rootdir, fname)
            relpath = os.path.relpath(total_path, infolderpath)
            with open(total_path, "rb") as f:
                raw = f.read()
            raw_b64 = base64.b64encode(raw).decode()
            blob, salt, nonce = encryptAESGCM(raw_b64, password)
            blobname, saltname, noncename = encryptAESGCM(relpath, password)
            encrypted_tree[blobname] = {
                "blob": blob,
                "salt": salt,
                "nonce": nonce,
                "blobname": blobname,
                "saltname": saltname,
                "noncename": noncename
            }
    def _encrypt_worker():
        for encname, data in encrypted_tree.items():
            relpath = decryptAESGCM(encname, password, data["saltname"], data["noncename"])
            size = _human(len(base64.b64decode(data["blob"])))
            appendscroll(folderscroll, f"encrypted: {relpath} ({size})", True, True)
        result = {
            "data": encrypted_tree,
            "key": os.path.basename(skeypath),
            "name": "ssfss:unused",
            "app": "ssfss",
            "type": "ss2f",
            "ver": VERSION,
            "stamp": time.time()
        }
        out_data = byte2base64(text2compressed(json.dumps(result)))
        write(outfilepath, out_data)
        def done():
            size = os.path.getsize(outfilepath)
            appendscroll(folderscroll, f"success: encrypted as .ss2f ({size} bytes)", True, True)
            appendscroll(folderscroll, "=" * 40, True, True)
            messagebox.showinfo("encrypted", f"folder saved to {outfilepath}")
        root.after(0, done)
    threading.Thread(target=_encrypt_worker).start()

def fodec():
    welcome = (
        "=== ssfss folder decryption utility for .ss2f files ===\n"
        f"version : {VERSION}\n"
        f"date and time : {gettime()}"
    )
    writescroll(folderscroll, welcome, True)
    skeypath = keypath.get()
    if not skeypath or skeypath == ".skey path":
        messagebox.showerror("error", "no .skey is selected, please select a path")
        appendscroll(folderscroll, "error: no .skey is selected, please select a path", True, True)
        return
    masterkey = masterkeyvar.get()
    if not masterkey:
        messagebox.showerror("error", "no master key selected")
        appendscroll(folderscroll, "error: no master key selected", True, True)
        return
    infilepath = filedialog.askopenfilename(
        title="load a .ss2f file",
        initialdir=BASEDIR,
        filetypes=[("super secure multiple/folder file", "*.ss2f")]
    )
    if not infilepath:
        messagebox.showerror("error", "no path selected for decrypting the .ss2f")
        appendscroll(folderscroll, "error: no path selected for decrypting the .ss2f", True, True)
        return
    appendscroll(folderscroll, "reading and loading .ss2f ...", True, True)
    data_base64 = read(infilepath)
    data_compressed = base642byte(data_base64)
    data_json = compressed2text(data_compressed)
    data = json.loads(data_json)
    if data.get('app') != 'ssfss' or data.get('type') != 'ss2f':
        messagebox.showerror("error", "invalid .ss2f file")
        appendscroll(folderscroll, "error: invalid .ss2f file format", True, True)
        return
    if data.get('ver') != VERSION:
        messagebox.showwarning("warning", f"version mismatch (file: {data['ver']}, app: {VERSION})")
    dest_folder = filedialog.askdirectory(
        title="select destination folder",
        initialdir=BASEDIR
    )
    if not dest_folder:
        messagebox.showerror("error", "no destination folder selected")
        appendscroll(folderscroll, "error: no destination folder selected", True, True)
        return
    os.makedirs(dest_folder, exist_ok=True)
    appendscroll(folderscroll, "reading and loading .skey ...", True, True)
    data4SKEY = read(skeypath)
    data3SKEY = base642byte(data4SKEY)
    data2SKEY = compressed2text(data3SKEY)
    dataSKEY = json.loads(data2SKEY)
    blobSKEY = dataSKEY["enc"]["blob"]
    saltSKEY = dataSKEY["enc"]["salt"]
    ivSKEY = dataSKEY["enc"]["iv"]
    appendscroll(folderscroll, "decrypting .skey ...", True, True)
    password = keydecode(decryptAESGCM(blobSKEY, masterkey, saltSKEY, ivSKEY))
    progress = {'completed': 0, 'total': len(data['data'])}
    def _decrypt_folder():
        for encname, meta in data['data'].items():
            try:
                relpath = decryptAESGCM(encname, password, meta['saltname'], meta['noncename'])
                decrypted_b64 = decryptAESGCM(meta['blob'], password, meta['salt'], meta['nonce'])
                file_data = base64.b64decode(decrypted_b64)
                outpath = os.path.join(dest_folder, relpath)
                os.makedirs(os.path.dirname(outpath), exist_ok=True)
                with open(outpath, 'wb') as f:
                    f.write(file_data)
                size_str = _human(len(file_data))
                appendscroll(folderscroll, f"decrypted: {outpath} ({size_str})", True, True)
                progress['completed'] += 1
            except Exception as e:
                messagebox.showerror("error", f"error decrypting a file: {e}")
                appendscroll(folderscroll, f"error decrypting one of the files: {e}", True, True)
    def _complete():
        messagebox.showinfo("decrypted", f"folder decrypted to {dest_folder}")
        appendscroll(folderscroll, f"success: decrypted folder saved to {dest_folder}", True, True)
        appendscroll(folderscroll, "=" * 40, True, True)
    def worker():
        _decrypt_folder()
        root.after(0, _complete)
    threading.Thread(target=worker).start()

root = Tk()
textframe = Frame(root)
fileframe = Frame(root)
folderframe = Frame(root)
infoframe = Frame(root)
fontsize = IntVar(value=11)
height = IntVar(value=20)
width = IntVar(value=80)
masterkeyvar = StringVar()
keypath = StringVar(value=".skey path")
root.title(f"ssfss v{VERSION}")
Label(root, text=f"ssfss super secure file storage system v{VERSION}").grid(row=0, column=0, columnspan=5)
Label(root, text="modes:").grid(row=1, column=0)
textbtn = Button(root, text="text", command=lambda: showframe(textframe))
textbtn.grid(row=1, column=1)
filebtn = Button(root, text="file", command=lambda: showframe(fileframe))
filebtn.grid(row=1, column=2)
folderbtn = Button(root, text="folder", command=lambda: showframe(folderframe))
folderbtn.grid(row=1, column=3)
infobtn = Button(root, text="info", command=lambda: showframe(infoframe))
infobtn.grid(row=1, column=4)
Label(root, text="settings:").grid(row=2, column=0)
fontent = Entry(root, width=16, textvariable=fontsize, font=("Consolas", 11))
fontent.grid(row=2, column=1)
heightent = Entry(root, width=16, textvariable=height, font=("Consolas", 11))
heightent.grid(row=2, column=2)
widthent = Entry(root, width=16, textvariable=width, font=("Consolas", 11))
widthent.grid(row=2, column=3)
wrapselector = Combobox(root, values=["CHAR", "WORD"], state="readonly", width=7)
wrapselector.grid(row=2, column=4)
wrapselector.set("WORD")
setbtn = Button(root, text="set", command=updateui)
setbtn.grid(row=3, column=0)
Label(root, text="font").grid(row=3, column=1)
Label(root, text="height").grid(row=3, column=2)
Label(root, text="width").grid(row=3, column=3)
Label(root, text="wrap").grid(row=3, column=4)
Label(root, text=".skey:").grid(row=4, column=0)
keypathent = Entry(root, width=34, textvariable=keypath, font=("Consolas", 11), state=DISABLED)
keypathent.grid(row=4, column=1, columnspan=2)
keypathbtn = Button(root, text="select .skey", command=skeyselect)
keypathbtn.grid(row=4, column=3)
keypathbtn = Button(root, text="create .skey", command=skeycreate)
keypathbtn.grid(row=4, column=4)
Label(root, text="master key:").grid(row=5, column=0)
passwordent = Entry(root, width=34, font=("Consolas", 11), state=DISABLED)
passwordent.grid(row=5, column=1, columnspan=2)
writeentry(passwordent, "press 'enter master key'", True)
passwordbtn = Button(root, text="enter master key", command=skeypassword)
passwordbtn.grid(row=5, column=3)
passwordforgetbtn = Button(root, text="forget master key & .skey", command=skeyforget)
passwordforgetbtn.grid(row=5, column=4)

Label(textframe, text="text encryption, .sstf (super secure text file)").grid(row=0, column=0, columnspan=4)
textscroll = scrolledtext.ScrolledText(textframe, wrap=WORD, width=80, height=20, font=("Consolas", 11))
textscroll.grid(row=1, column=0, columnspan=4)
savetextbtn = Button(textframe, text="encrypt .sstf", command=teenc)
savetextbtn.grid(row=2, column=0, columnspan=2)
loadtextbtn = Button(textframe, text="decrypt .sstf", command=tedec)
loadtextbtn.grid(row=2, column=2, columnspan=2)
timebtn = Button(textframe, text="append time", command=timeappend)
timebtn.grid(row=3, column=0)
Label(textframe, text="length: ").grid(row=3, column=1)
lenent = Entry(textframe, width=16, font=("Consolas", 11))
lenent.grid(row=3, column=2)
Label(textframe, text="chars").grid(row=3, column=3)

Label(fileframe, text="file encryption, .ss1f (super secure singular file)").grid(row=0, column=0, columnspan=2)
filescroll = scrolledtext.ScrolledText(fileframe, state=DISABLED, wrap=WORD, width=80, height=20, font=("Consolas", 11))
filescroll.grid(row=1, column=0, columnspan=2)
savefilebtn = Button(fileframe, text="encrypt .ss1f", command=fienc)
savefilebtn.grid(row=2, column=0)
loadfilebtn = Button(fileframe, text="decrypt .ss1f", command=fidec)
loadfilebtn.grid(row=2, column=1)

Label(folderframe, text="folder encryption, .ss2f (super secure multiple/folder file)").grid(row=0, column=0, columnspan=2)
folderscroll = scrolledtext.ScrolledText(folderframe, state=DISABLED, wrap=WORD, width=80, height=20, font=("Consolas", 11))
folderscroll.grid(row=1, column=0, columnspan=2)
savefolderbtn = Button(folderframe, text="encrypt .ss2f", command=foenc)
savefolderbtn.grid(row=2, column=0)
loadfolderbtn = Button(folderframe, text="decrypt .ss2f", command=fodec)
loadfolderbtn.grid(row=2, column=1)

Label(infoframe, text="information").grid(row=0, column=0)
infoscroll = scrolledtext.ScrolledText(infoframe, state=DISABLED, wrap=WORD, width=80, height=20, font=("Consolas", 11))
infoscroll.grid(row=1, column=0)
infoscrolltext = (
    "ssfss, super secure file storage system: https://github.com/bruh-moment-0/ssfss\n"
    "supports text, file and folder encryption\n"
    "uses aes 256 gcm argon2id and safe keys (.skey) to store keys. .skey's can only be unlocked with a master key that the user is supposed to keep safe\n"
    "REMEMBER: Silence means security, loose lips might sink ships! (OPSEC)\n"
    "this program is not licensed. use it at your will.\n"
    "CHANGE LOGS:\n"
    "v3.1 - changed the folder encryption logic a bit, the old one told the base folders name in plaintext, but due to tkinter limitations,\n"
    "       the 'name' key on .ss2f files are unused.\n"
    "v3.0 - changed the password hashing algorithm to argon2id, before it was PBKDF2, this made the encryption more safer.\n"
    "       now bruteforcing is even more impossible.\n"
    "v2.0 - added name encryption to .ss1f and .ss2f, this makes the encryption better, as now guessing what the file is impossible.\n"
    "       fixed some problems.\n"
    "v1.0 - program released."
)
writescroll(infoscroll, infoscrolltext, True)
loop()
root.mainloop()
