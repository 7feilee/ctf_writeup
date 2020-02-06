from pwn import *
import threading
mutex = threading.Lock()

def worker():
    print "Thread started"
    while True:
        c = connect("problem1.tjctf.org", 8007)
        for _ in range(30):
            a  = []
            for __ in range(40):
                c.recv()
                c.sendline("bjacdefghi")
                a.append(c.recvline())
            mutex.acquire()
            f = open("fix10", "a")
            f.write("".join(a))
            f.close()
            mutex.release()

for i in range(50):
    threading.Thread(target=worker).start()