import requests
#DST_BASE = "140.122.185.210:8080"
DST_BASE = "127.0.0.1:5000"
ORACLE_BASE = f"http://{DST_BASE}/oracle"

CT = bytes.fromhex("00112233445566778899aabbccddeefff11d6be0ffca720cd9a3000e2df15436c0fcb4624f7181f882f15f1addf78297426ec183a45eabc879b691c84b1875483859e5f83eab250204b2ea5a0c246713ddcbac593fe30fba7d2aa31f1070c7cd50ed7bc37fd77308da5f55ee7317f09aa4375d2078014d361d023550cb19faac40e03c9d6f05b5c660500ef1dfdbd6db")

#CT = bytes.fromhex("00112233445566778899aabbccddeefff9473924bd62ba19f2dd19c30928947765786c8d4972fd132ec97a3a3e5181917652a0dc44cb493881bdd841103b8bca2d4824eef54b306f093bdc5a17dc9f46a862217ecb6b80244fdba90fbb13c72bab3de8d9653be21d635a0f8d5971283606eb64c0fbb922afd9db007f94fb9e24a899a6c0a65b687b85f45d4840d47df4")
BLOCK_SZ = 16

def send_oracle(ct:bytes)->bool:
    with requests.get(f"{ORACLE_BASE}/{ct.hex()}") as resp:
        txt = resp.text
        if txt == "valid":
            return True
        elif txt == "invalid":
            return False
        raise Exception(f"receive text :{txt}")

def xor_bytes(a:bytes, b:bytes)->bytes:
    if len(a) != len(b):
        raise ValueError(f"a:{a}\nb:{b}")
    return bytes([a[i]^b[i] for i in range(len(a))])

def set_bytes_char(b:bytes, c:int, offset:int)->bytes:    
    li = list(b)
    li[offset] = c
    return bytes(li)

def padding_oracle_unit(offset:int)->bytes:
    iv = CT[offset*BLOCK_SZ:(offset+1)*BLOCK_SZ]
    ct = CT[(offset+1)*BLOCK_SZ:(offset+2)*BLOCK_SZ]
    guess_msg = b'\x00'*BLOCK_SZ
    for pad_len in range(1, BLOCK_SZ+1):
        # craft desirable pad mask
        pad_msk = b'\x00'*(BLOCK_SZ - pad_len) + bytes([pad_len] * pad_len)

        ans_set = []
        for ch in range(256):
            n_msg = set_bytes_char(guess_msg, ch, BLOCK_SZ - pad_len)
            msg_xor_iv = xor_bytes(iv, n_msg)
            n_iv = xor_bytes(msg_xor_iv, pad_msk)
            if send_oracle(n_iv+ct):
                ans_set.append(ch)
        
        if len(ans_set) == 0:
            raise Exception("no ans in answer set...")
        elif len(ans_set) != 1:
            print(f"[Warning] ans set has multiple answer {ans_set}")
        guess_msg = set_bytes_char(guess_msg, ans_set[-1], BLOCK_SZ - pad_len)
        print(f"found {guess_msg}")

    return guess_msg

def padding_oracle()->str:
    pt = b""
    print(f"[total rounds: {len(CT)//BLOCK_SZ - 1}]")
    for i in range(len(CT)//BLOCK_SZ - 1):
        print(f"[start padding oracle unit {i}]")
        #input("[start]")
        pt += padding_oracle_unit(i)
    return pt

def main():
    print(padding_oracle())

if __name__ == "__main__":
    main()