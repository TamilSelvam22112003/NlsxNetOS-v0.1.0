import fcntl,os,struct
TUNSETIFF=0x400454CA; IFF_TUN=0x0001; IFF_NO_PI=0x1000
class TunDevice:
 def __init__(self,name="nls0"): self.name=name; self.fd=None
 def open(self):
  if not os.path.exists("/dev/net/tun"): raise RuntimeError("/dev/net/tun is unavailable")
  self.fd=os.open("/dev/net/tun",os.O_RDWR|os.O_NONBLOCK)
  result=fcntl.ioctl(self.fd,TUNSETIFF,struct.pack("16sH22s",self.name.encode()[:15],IFF_TUN|IFF_NO_PI,b""))
  self.name=result[:16].split(b"\x00",1)[0].decode(); return self
 def read(self,size=65535): return os.read(self.fd,size)
 def write(self,packet): return os.write(self.fd,packet)
 def fileno(self): return self.fd
 def close(self):
  if self.fd is not None: os.close(self.fd); self.fd=None
