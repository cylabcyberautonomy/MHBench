#!/usr/bin/env python3
# Raw TCP passthrough (no TLS termination) — the mgmt-host analog of the 9200 relay, for server-mediated
# EDRs (Velociraptor). Usage: tcp_forward.py <listen_port> <dst_host> <dst_port>
import socket, sys, threading
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except Exception: pass
    finally:
        for s in (a, b):
            try: s.close()
            except Exception: pass
def handle(client, dh, dp):
    try: server = socket.create_connection((dh, dp), timeout=10)
    except Exception: client.close(); return
    threading.Thread(target=pipe, args=(client, server), daemon=True).start()
    threading.Thread(target=pipe, args=(server, client), daemon=True).start()
lp=int(sys.argv[1]); dh=sys.argv[2]; dp=int(sys.argv[3])
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",lp)); s.listen(128)
while True:
    c,_=s.accept(); threading.Thread(target=handle,args=(c,dh,dp),daemon=True).start()
