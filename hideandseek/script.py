import base64
from http.client import NOT_EXTENDED
import re

# opening the image file
with open("./main.png", 'rb') as f:
    data = f.read()

# print(data)
# to find all the "eDIH" chunks in image data using regex
needed = []
for loc in re.finditer(b"eDIH", data):
    # print(loc.end())
    needed.append(loc.end())

flag = ""

for i in needed:
    # print(chr(data[i]))
    flag += chr(data[i])

print(flag)

# OUTPUT : Q1RGe0RpZFlvdUtub3dQTkdpc1Byb25vdW5jZWRQSU5HP30=

# Decoding from base 64

print(base64.b64decode(flag))