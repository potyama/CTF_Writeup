from pwn import *

HOST = "5.75.193.99"
PORT = 11311

PTE_PRIMES_LHS = [
    32058169621, 32367046651, 32732083141, 33883352071,
    34585345321, 35680454791, 36915962911, 38011072381,
    38713065631, 39864334561, 40229371051, 40538248081
]
PTE_PRIMES_RHS = [
    32142408811, 32198568271, 32900561521, 33658714231,
    34978461541, 35315418301, 37280999401, 37617956161,
    38937703471, 39695856181, 40397849431, 40454008891
]

def make_num(nbit):

    if nbit == 2:
        return [1, 2], [3]
    elif nbit == 3:
        return [1, 6, 8], [2, 4, 9]
    elif nbit == 4:
        return [1, 5, 8, 12, 18, 19], [2, 3, 9, 13, 16, 20]

    lhs = PTE_PRIMES_LHS[:]
    rhs = PTE_PRIMES_RHS[:]

    lower = 2 ** (nbit - 1)

    current_size = len(lhs) + len(rhs)
    if current_size < lower:
        add_zero = lower - current_size
        lhs.extend([0]*add_zero)

    return lhs, rhs

LEVEL = 0
def main():
    r = remote(HOST, PORT)
    while True:
        try:
            data = r.recvuntil(b"Options:").decode()
            r.sendline(b"I")
            line = r.recvline().decode().strip()

            while True:
                line = r.recvline().decode().strip()
                print(f"Received line: {line}")
                if "nbit =" in line:
                    try:
                        nbit = int(line.split("=")[-1].strip())
                        LEVEL = nbit
                        print(f"Parsed nbit: {nbit}")
                        break
                    except ValueError:
                        print("Failed to parse nbit.")
                        break

            print(LEVEL)
            data = r.recvuntil(b"Options:").decode()
            print("--- Server menu again ---")
            print(data)

            r.sendline(b"s")

            r.recvuntil(b"Please send the elements of first set I_1: ")

            I1, I2 = make_num(nbit)
            print(f"[SOLVE] I1={I1}")
            print(f"[SOLVE] I2={I2}")

            r.sendline(",".join(map(str, I1)).encode())

            r.recvuntil(b"Now please send the elements of second set I_2: ")

            r.sendline(",".join(map(str, I2)).encode())

            if LEVEL >= 9:
                try:
                    line = r.recvline().decode()
                    line = r.recvline().decode()
                    flag = r.recvline().decode()

                    print(repr(flag))
                    r.close()
                except:
                    pass

        except EOFError:
            print("EOFError: The server closed the connection unexpectedly.")
            break
        except Exception as e:
            print(f"Exception occurred: {e}")
            break

    r.close()

if __name__ == "__main__":
    main()
