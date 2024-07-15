from AES import AES

input = "deadbeefdeadbeefdeadbeefdeadbeef"
key = "deadbeefdeadbeefdeadbeefdeadbeef" 

example = AES(input, key)

output = example.Cipher()
print(f"\n{example.toString(output)} <--- cipher")

inv_output = example.InvCipher()
print(f"{example.toString(inv_output)} <--- inverse cipher\n\n")

print("↓ ↓ ↓ round keys ↓ ↓ ↓ ")
round_keys = example.getRoundKeys()
for round_key in round_keys:
    print(example.parseWords(example.toString(round_key)))

rounds = example.getRounds()
print("\n\n↓ ↓ ↓ rounds ↓ ↓ ↓ \n"+rounds)


# whitespace test
key = "2B 7 E15  1 628  A ED2  A 6 A B  F7 15 8809CF4F3C"
text = "32 43 f 6 a 8     88 5a3  08d 3131 98 a2e0370734"
test = AES(text, key) 

print('\n')
cipher = test.Cipher()
print(test.toString(cipher))

print('\n')
invcipher = test.InvCipher()
print(test.toString(invcipher))


# appendix A key expansion testing
txt = "deadbeefdeadbeefdeadbeefdeadbeef"

print('\n')
keyExpansion128 = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
test2 = AES(txt, keyExpansion128)
rk = test2.getRoundKeys()
for i in rk:
    print(test2.parseWords(test2.toString(i)))
    
print('\n')
keyExpansion192 = "8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b"
test3 = AES(txt, keyExpansion192)
rk = test3.getRoundKeys()
for i in rk:
    print(test3.parseWords(test3.toString(i)))

print('\n')
keyExpansion256 = "60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4"
test4 = AES(txt, keyExpansion256)
rk = test4.getRoundKeys()
for i in rk:
    print(test4.parseWords(test4.toString(i)))


# appendix B intermedite value testing
print('\n')
Input = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34"
Cipher_Key = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c"
example = AES(Input, Cipher_Key)
example.Cipher()
example.InvCipher()
print(example.getRounds())


# appendix C more intermediate value testing
print('\n')
PLAINTEXT = "00112233445566778899aabbccddeeff"
KEY = "000102030405060708090a0b0c0d0e0f" # 128 bit
test = AES(PLAINTEXT, KEY)
test.Cipher()
test.InvCipher()
print(test.getRounds())

print('\n')
PLAINTEXT = "00112233445566778899aabbccddeeff"
KEY = "000102030405060708090a0b0c0d0e0f1011121314151617" # 192 bit 
test = AES(PLAINTEXT, KEY)
test.Cipher()
test.InvCipher()
print(test.getRounds())

print('\n')
PLAINTEXT = "00112233445566778899aabbccddeeff"
KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" # 256 bit 
test = AES(PLAINTEXT, KEY)
test.Cipher()
test.InvCipher()
print(test.getRounds())


# other test cases 
print('\n')
PLAINTEXT = ""
KEY = "deadbeefdeadbeefdeadbeefdeadbeef" 
try: 
    test = AES(PLAINTEXT, KEY)
except ValueError as e:
    print(e) 

print('\n')
PLAINTEXT = ""
KEY = "" 
try: 
    test = AES(PLAINTEXT, KEY)
except ValueError as e:
    print(e) 
    
print('\n')
PLAINTEXT = "deadbeefdeadbeefdeadbeefdeadbeef"
KEY = "" 
try: 
    test = AES(PLAINTEXT, KEY)
except ValueError as e:
    print(e) 
    
print('\n')
PLAINTEXT = "!@#$#%!@$%@#$!@#!@#!#$!@#!@#!%^!"
KEY = "deadbeefdeadbeefdeadbeefdeadbeef" 
try: 
    test = AES(PLAINTEXT, KEY)
except ValueError as e:
    print(e) 

print('\n')
PLAINTEXT = "deadbeefdeadbeefdeadbeefdeadbeef"
KEY = "!@#$#%!@$%@#$!@#!@#!#$!@#!@#!%^!" 
try: 
    test = AES(PLAINTEXT, KEY)
except ValueError as e:
    print(e)
