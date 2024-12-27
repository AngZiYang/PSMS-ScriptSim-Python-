# Import necessary modules from the PyCryptodome library
from Crypto.PublicKey import DSA  # For generating DSA key pairs
from Crypto.Signature import DSS  # For signing messages with DSA
from Crypto.Hash import SHA256  # For hashing messages with SHA256
import binascii  # For converting binary data to hexadecimal format

# Function to create P2MS scripts
def create_p2ms_script(m, n, iteration):
    """
    Generates scriptPubKey and scriptSig for Pay-to-Multi-Signature (P2MS).

    Args:
        m (int): Number of required signatures.
        n (int): Number of public/private key pairs.
        iteration (int): Iteration number for file naming.
    """
    if n < m:
        raise ValueError("N must be greater or equal to M")

    # Generate N key pairs (public and private keys)
    key_pairs = [DSA.generate(1024) for _ in range(n)]
    
    # Prepare the message to be signed
    msg = b"CSCI301 Contemporary Topics in Security 2024"
    h = SHA256.new(msg)  # Hash the message

    # Generate M signatures using the first M private keys
    signatures = []
    for i in range(m):
        signer = DSS.new(key_pairs[i], 'fips-186-3')  # Initialize signer with private key
        signatures.append(signer.sign(h))  # Sign the hashed message

    # File names for output
    pf_name = f"scriptPubKey_{iteration}.txt"
    sf_name = f"scriptSig_{iteration}.txt"

    # Write scriptPubKey to a file
    with open(pf_name, 'w') as f:
        f.write("OP_M {}\n".format(m))  # Number of required signatures
        for key in key_pairs:
            # Write public keys in hexadecimal format
            f.write("{}\n".format(binascii.hexlify(key.publickey().export_key(format='DER')).decode('utf-8')))
        f.write("OP_N {}\nOP_CHECKMULTISIG".format(n))  # Number of public keys and script operator

    # Write scriptSig to a file
    with open(sf_name, 'w') as f:
        for sig in signatures:
            # Write signatures in hexadecimal format
            f.write("{}\n".format(binascii.hexlify(sig).decode('utf-8')))

# User input for the number of signatures (M) and key pairs (N)
m = int(input("Please enter number of signatures (M): "))
n = int(input("Please enter number of key pairs (N): "))

# Generate three different pairs of scriptSig and scriptPubKey
for i in range(1, 4):
    create_p2ms_script(m, n, i)  # Call the function for each iteration
    print(f"Generated scriptPubKey_{i}.txt and scriptSig_{i}.txt")
