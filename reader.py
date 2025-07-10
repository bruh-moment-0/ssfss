import base64
import zlib
import json

def decode_and_decompress_from_file(filepath):
    with open(filepath, 'r') as f:
        data_b64 = f.read()
    compressed_data = base64.b64decode(data_b64)
    decompressed_data = zlib.decompress(compressed_data)
    return decompressed_data

while True:
    print("======")
    input_path = input("path? ")
    result = json.loads(decode_and_decompress_from_file(input_path))
    print()
    print(json.dumps(result, indent=4))
    print()