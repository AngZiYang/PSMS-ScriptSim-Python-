# Import necessary modules from the PyCryptodome library
from Crypto.PublicKey import DSA  # For importing DSA public keys
from Crypto.Signature import DSS  # For verifying DSA signatures
from Crypto.Hash import SHA256  # For hashing messages with SHA256
import binascii  # For converting hexadecimal data to binary

# Function to verify a single signature
def verify_signature(public_key, signature, message):
    """
    Verifies a single DSA signature.

    Args:
        public_key (DSA key): Public key used for verification.
        signature (bytes): Signature to verify.
        message (bytes): Message that was signed.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    h = SHA256.new(message)  # Hash the message
    verifier = DSS.new(public_key, 'fips-186-3')  # Initialize verifier with public key
    try:
        verifier.verify(h, signature)  # Verify the signature
        return True
    except ValueError:
        return False

# Function to execute the P2MS script
def execute_p2ms_script(p_file, s_file):
    """
    Executes the P2MS script by verifying signatures against public keys.

    Args:
        p_file (str): File name of scriptPubKey.
        s_file (str): File name of scriptSig.

    Returns:
        bool: True if the script executes successfully, False otherwise.
    """
    # Read the scriptPubKey file
    with open(p_file, 'r') as f:
        lines = f.readlines()
    
    # Check if OP_CHECKMULTISIG exists at the end of scriptPubKey
    if 'OP_CHECKMULTISIG' not in lines[-1]:
        print("Invalid scriptPubKey format: OP_CHECKMULTISIG missing.")
        return False

    m = int(lines[0].split()[1])  # Number of required signatures
    # Extract public keys from the file
    public_keys = [DSA.import_key(binascii.unhexlify(line.strip())) for line in lines[1:-2]]

    # Read the scriptSig file
    with open(s_file, 'r') as f:
        # Extract signatures from the file
        signatures = [binascii.unhexlify(line.strip()) for line in f]

    msg = b"CSCI301 Contemporary Topics in Security 2024"  # Message to verify
    valid_signatures = 0  # Counter for valid signatures

    # Verify each signature against all public keys
    for sig in signatures:
        for pk in public_keys:
            if verify_signature(pk, sig, msg):  # Check if the signature is valid
                valid_signatures += 1
                break  # Move to the next signature after a successful verification

    return valid_signatures >= m  # Return True if valid signatures meet or exceed M

# User input for scriptPubKey and scriptSig file names
p_file = input("Please enter scriptPubKey file name: ")
s_file = input("Please enter scriptSig file name: ")

# Execute the P2MS script and print the result
if execute_p2ms_script(p_file, s_file):
    print("Script executed successfully: True")
else:
    print("Script execution failed: False")
