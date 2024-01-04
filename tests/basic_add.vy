stor_a: public(uint256)

@external
def __init__(_stor_a: uint256):
    self.stor_a = _stor_a

@external
def basic_add256(a: uint256, b: uint256) -> uint256:
    return a + b
    # return a + b + self.stor_a
