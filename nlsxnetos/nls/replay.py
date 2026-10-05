class ReplayWindow:
    def __init__(self,size=64):
        if not 1<=size<=4096: raise ValueError("window size must be 1..4096")
        self.size=size; self.highest=-1; self.bitmap=0
    def accept(self,sequence):
        if sequence<0: return False
        if self.highest<0: self.highest,self.bitmap=sequence,1; return True
        if sequence>self.highest:
            shift=sequence-self.highest; self.bitmap=((self.bitmap<<shift)|1)&((1<<self.size)-1); self.highest=sequence; return True
        offset=self.highest-sequence
        if offset>=self.size or self.bitmap&(1<<offset): return False
        self.bitmap|=1<<offset; return True
