class ReplayWindow:
 def __init__(self,size=64):
  if not 1<=size<=4096: raise ValueError("window size must be 1..4096")
  self.size=size; self.highest=-1; self.bitmap=0
 def can_accept(self,sequence):
  if sequence<0: return False
  if self.highest<0: return True
  if sequence>self.highest: return True
  offset=self.highest-sequence
  return offset<self.size and not (self.bitmap&(1<<offset))
 def mark(self,sequence):
  if not self.can_accept(sequence): return False
  if self.highest<0: self.highest,self.bitmap=sequence,1; return True
  if sequence>self.highest:
   shift=sequence-self.highest
   self.bitmap=((self.bitmap<<shift)|1)&((1<<self.size)-1); self.highest=sequence; return True
  self.bitmap|=1<<(self.highest-sequence); return True
 def accept(self,sequence):
  return self.mark(sequence)
