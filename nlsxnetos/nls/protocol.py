import struct,time
from .crypto import decrypt,encrypt
from .replay import ReplayWindow
MAGIC=b"NLS1"; HEADER=struct.Struct("!4sBQQ12s")
class NLSProtocol:
    def __init__(self,key,replay_window=64,max_clock_skew=120):
        if len(key)!=32: raise ValueError("NLS key must be 32 bytes")
        self.key=key; self.replay=ReplayWindow(replay_window); self.max_clock_skew=max_clock_skew
    def seal(self,sequence,plaintext,timestamp=None):
        timestamp=int(time.time()) if timestamp is None else int(timestamp)
        aad=MAGIC+struct.pack("!BQQ",1,sequence,timestamp); nonce,ciphertext=encrypt(self.key,plaintext,aad)
        return HEADER.pack(MAGIC,1,sequence,timestamp,nonce)+ciphertext
    def open(self,packet):
        if len(packet)<HEADER.size+16: raise ValueError("NLS packet is too short")
        magic,version,sequence,timestamp,nonce=HEADER.unpack(packet[:HEADER.size])
        if magic!=MAGIC or version!=1: raise ValueError("unsupported NLS packet")
        if abs(int(time.time())-timestamp)>self.max_clock_skew: raise ValueError("NLS timestamp outside allowed clock skew")
        if not self.replay.accept(sequence): raise ValueError("NLS replay detected")
        aad=MAGIC+struct.pack("!BQQ",version,sequence,timestamp)
        return decrypt(self.key,nonce,packet[HEADER.size:],aad)
