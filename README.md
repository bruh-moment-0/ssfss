# ssfss version 3.2
super secure file storage system, uses advanced encryption standard in galois/counter mode (aes-gcm) with argon2id for secure text, file and folder encryption, featuring a graphical user interface. see the update logs from the information area in the program.

## features  
- highly secure – if you protect your `.skey` and its master key, not even the cia, fbi, nsa, or any other entity can decrypt your data
- user-friendly – simple tkinter-based gui.  
- fast performance – uses the threading module for improved speed.  
- customizable ui – some gui elements can be modified.  
- flexible encryption – encrypts messages, files, or entire folders.  
- privacy-focused – no hidden info-stealers or shady backdoors.
- tamper-protected – refuses to work if the program is tampered.

## how to run it?
1. install python (minimum requirement: python 3.6) from [python.org](https://www.python.org/downloads/).  
2. run `installer.py` to install the required dependencies.  
3. launch `main.py` to start the application.

## how to use it?
1. complete the initial setup.  
2. launch `main.py` to start the application.
3. press `create .skey` and follow the instructions
4. press `select .skey` and follow the instructions
5. press `enter master key` and follow the instructions
6. after this point, if you want to remove master key and `.skey` from memory press `forget master key & .skey`
7. choose your mode (`text`, `file`, `folder`)
8. press `encrypt .ssXf` and follow the instructions to encrypt
9. press `decrypt .ssXf` and follow the instructions to decrypt
10. encrypt or decrypt messages/files as needed.

## disadvantages
1. if you lose your `.skey` and your master key there is no way in hell you are getting them back. you have to have them both at the same time.

## finally,
there is a python file called `reader.py`, run it and put any file output of this program (`.skey`, `.sstf`, `.ss1f`, `.ss2f`) you can see the `json` format of those files. an intruder would be only able to see that much information without your `.skey` and your master key.
