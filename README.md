# ssfss version 3.2
super secure file storage system, uses advanced encryption standard 256 bit in galois/counter mode (AES-256-GCM) with Argon2id for secure text, file and folder encryption, featuring a graphical user interface. see the update logs from the information area in the program.

## features  
- highly secure – if you protect your `.skey` and its master key, not even the cia, fbi, nsa, or any other entity can decrypt your data
- user-friendly – simple tkinter-based gui.  
- fast performance – uses the threading module for improved speed.  
- customizable ui – some gui elements can be modified.  
- flexible encryption – encrypts messages, files, or entire folders.  
- privacy-focused – no hidden info-stealers or shady backdoors.
- tamper-protected – refuses to work if the program is tampered.

## how it works
when you create a `.skey` file using your master key, the program securely generates a unique 256-bit encryption key. this key is then safely encrypted using your master key and stored inside the `.skey` file. whenever you need to encrypt or decrypt files, the program uses the `.skey` file along with the master key to retrieve the original 256-bit encryption key. this setup ensures strong security — an attacker can't easily brute-force your files, even if the script didnt use argon2id. however, it's important to store your `.skey` file somewhere safe and away from potential attackers. while the file is encrypted and not immediately useful on its own, it still holds sensitive material — so treat it with care. due to the insane protection, you and your files are safe.

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
1. if you lose your `.skey` and your master key there is no way in hell you are getting your files back. you have to have them both at the same time.

## finally,
there is a python file called `reader.py`, run it and put any file output of this program (`.skey`, `.sstf`, `.ss1f`, `.ss2f`) you can see the `json` format of those files. an intruder would be only able to see that much information without your `.skey` and your master key.
