import subprocess
import sys

libraries = {
    'pycryptodome': {'install': 'pycryptodome', 'import': 'Crypto'},
    'argon2-cffi': {'install': 'argon2-cffi', 'import': 'argon2.low_level'},
}

def install(libraries):
    for name, lib in libraries.items():
        try:
            __import__(lib['import'])
            print(f"{name} is already installed.")
        except ImportError:
            print(f"{name} is not installed. installing...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', lib['install']])
                print(f"{name} installed successfully.")
            except subprocess.CalledProcessError:
                print(f"failed to install {name}. please check your environment and try again. unknown error returned from subprocess module")
                continue
            except FileNotFoundError:
                print("pip not found. installing pip...")
                try:
                    subprocess.check_call([sys.executable, '-m', 'ensurepip'])
                    print("pip installed successfully.")
                except subprocess.CalledProcessError:
                    print("failed to install pip. please check your environment and try again. unknown error returned from subprocess module")
                    continue

print("press ENTER to start the installer:")
input()
install(libraries)
print("done installing the required libraries.")
print("press ENTER to exit.")
input()