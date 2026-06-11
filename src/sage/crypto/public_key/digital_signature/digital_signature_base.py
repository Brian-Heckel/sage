from sage.structure.sage_object import SageObject
from sage.misc.superseded import experimental_warning
from abc import abstractmethod

from typing import Any

experimental_warning(
    41218,
    "SageMath's digital signature functionality is experimental and might change in the future.",
)


class DigitalSignatureBase(SageObject):
    """
    A base class for Cryptographic Signature Schemes
    """
    
    @abstractmethod
    def generate_keys(self) -> tuple[Any, Any]:
        """
        Generates a (public_key, secret_key) pair that is used for a signature
        """
        raise NotImplementedError

    @abstractmethod
    def sign(self, message, secret_key):
        """
        Returns the (signature, message) pair that was signed by the secret key.
        """
        raise NotImplentedError
    
    @abstractmethod
    def verify(self, public_key, signature, message):
        """
        From the public key and the signature and message, returns true if the signature is
        valid and returns false if the signature is not valid.
        """
        raise NotImplementedError
    
    @abstractmethod
    def parameters(self):
        """
        Returns a tuple of the public parameter set
        """
        raise NotImplementedError

    def do_signature(self, message):
        public_key, secret_key = self.generate_keys()
        signature, message = self.sign(message, secret_key)
        result_of_verification = self.verify(public_key, signature, message)
        return public_key, secret_key, signature, message, result_of_verification

    def _repr_(self) -> str:
        return f'{type(self).__name__} with parameter set: {self.parameters()}'

    def __eq__(self, other) -> bool:
        return isinstance(other, type(self)) and self.parameters() == other.parameters()

    def __hash__(self) -> int:
        return hash(self.parameters())

    def _test_signature(self, **options):
        tester = self._tester(**options)
        message = randint(2, 2000)
        public_key, secret_key, signature, message, result = self.do_signature(message)
        tester.assertTrue(result)


          
