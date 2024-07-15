from PIL import Image
from AES import AES
import time

start = time.time()

path = 'C:/Users/gyduf/Desktop/duck.jpeg'
img = Image.open(path)

bytes = img.tobytes()

num0s = (16 - (len(bytes) % 16))

bytes += b'\x00' * num0s

bytelist = [bytes[i:i + 16] for i in range(0, len(bytes), 16)]

hex = [''.join(f'{byte:02x}' for byte in i) for i in bytelist]

result = ""
for i in hex:
    temp = AES(i, "deadbeefdeadbeefdeadbeefdeadbeef")
    result += temp.toString(temp.Cipher())

print(result)
print("\n%s secs" % (time.time() - start))
