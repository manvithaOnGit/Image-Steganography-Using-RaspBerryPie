# test_paillier.py
from phe import paillier
print("phe.paillier module:", paillier)
print("Has generate_paillier_keypair?:", hasattr(paillier, "generate_paillier_keypair"))
# Try generating keys (small test)
pub, priv = paillier.generate_paillier_keypair(1024)
print("Generated keys types:", type(pub), type(priv))
