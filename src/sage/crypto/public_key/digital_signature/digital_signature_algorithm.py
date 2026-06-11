
from .digital_signature_base import DigitalSignatureBase
from sage.misc.prandom import randint
from sage.rings.integer import Integer
from sage.rings.finite_rings.integer_mod_ring import IntegerModRing

class DigitalSignatureAlgorithm(DigitalSignatureBase):
    
    def __init__(self, p, q, g):
        # Used for field operation
        self.q = q
        self.p = p
        self.pZmod = IntegerModRing(p)
        self.qZmod = IntegerModRing(q)
        self.generator = self.pZmod(g)
        
    def secret_key(self):
        return randint(1, self.q-1)
    
    def generate_keys(self):
        secret_key = randint(1, self.q-1)
        public_key = self.pZmod(self.generator)**secret_key
        return (public_key, secret_key)

    def sign(self, message, secret_key):
        """
        signature is of the form (r, s)
        """
        k = Integer(randint(1, self.q-1))
        r = self.qZmod(self.pZmod(self.generator**k))
        s = self.qZmod(k)**(-1) * (self.qZmod(message) + self.qZmod(secret_key) * r)
        return ((r, s), message)
    
    def verify(self, public_key, signature, message):
        r, s = signature
        s = self.qZmod(s)
        w = s**(-1)
        u1 = self.qZmod(message) * w
        u2 = r * w
        v = self.qZmod(
            self.pZmod(self.generator)**u1 * self.pZmod(public_key)**u2
        )
        return v == r
    
    def parameters(self):
        return (self.p, self.q, self.generator)
