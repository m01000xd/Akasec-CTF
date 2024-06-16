![image](https://github.com/m01000xd/Akasec-CTF/assets/122852491/04a73311-2f70-43b4-97ca-0a94e6c09de1)

![image](https://github.com/m01000xd/Akasec-CTF/assets/122852491/96d84ba8-73e5-4e22-9a8e-1931a1a6922f)

![image](https://github.com/m01000xd/Akasec-CTF/assets/122852491/11478dc4-a832-47a1-bd9b-27284aa3bf1f)

![image](https://github.com/m01000xd/Akasec-CTF/assets/122852491/b6ad8c5c-4080-40d9-a2ca-90b430b0feba)

![image](https://github.com/m01000xd/Akasec-CTF/assets/122852491/403e2c26-02cf-402f-88f8-41a2d608c00a)

![image](https://github.com/m01000xd/Akasec-CTF/assets/122852491/d309571a-01b6-4331-bd67-969b33346ad4)

![image](https://github.com/m01000xd/Akasec-CTF/assets/122852491/2647c1d9-a962-4700-b97d-843e0585e582)

Chương trình kiểm tra ```flag``` nhập vào gồm 0x20(32 kí tự), sau đó được mã hóa qua 4 hàm ```encrypt```, được ```cipher``` đem so kết quả trong hàm ```check_func```.

4 hàm ```encrypt``` cấu trúc như nhau, chỉ cộng và xor các kí tự. Ta sẽ gộp cả 4 vào trong 1 file text, rồi sửa cộng thành trừ và read file từ dưới lên trên sẽ ra được flag.

### Script

```python3
import itertools
import ctypes
flag = []
flag.append(0x3167deae217139c1)
flag.append(0x6745aeaf0c9a62e5)
flag.append(0x62664d91c2da0c7b)
flag.append(0x7ee01bea8defde65)
lst = []
for line in reversed(list(open("chall.txt"))):
    a = line.rstrip()
    b = a.lstrip()
    exec(b)

a = [hex(ctypes.c_ulonglong(i).value) for i in flag]
s = [list(bytearray.fromhex(i.replace('0x',''))[::-1]) for i in a]
flag = list(itertools.chain.from_iterable(s))
print(''.join([chr(i) for i in flag]))
```

### Flag

    akasec{1n_my_b4g_0n3_s3c0nd_0n3}
