
import subprocess
import sys
import os
import re

def validate_hex_prefix(prefix):
    """Validate that the prefix is a valid hexadecimal string."""
    if not prefix:
        return False
    return re.match(r"^[0-9a-fA-F]+$", prefix) is not None

def generate_and_check(prefix):
    """
    Generates ED25519 keys using OpenSSL until the public key matches the prefix.
    """
    print(f"Searching for a public key starting with '{prefix}'...")
    prefix = prefix.lower()
    count = 0
    while True:
        count += 1
        try:
            # 1. Generate private key in PEM format
            gen_process = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ED25519"],
                capture_output=True,
                check=True,
                text=True  # Work with text for easier handling
            )
            private_key_pem = gen_process.stdout

            # 2. Extract public key in DER format from the private key
            pub_process = subprocess.run(
                ["openssl", "pkey", "-pubout", "-outform", "DER"],
                input=private_key_pem,
                capture_output=True,
                check=True,
                text=False # DER format is binary
            )
            public_key_der = pub_process.stdout

            # 3. The raw public key is the last 32 bytes of the DER output for ED25519
            #    (for SubjectPublicKeyInfo structure)
            if len(public_key_der) < 32:
                # This should not happen with a valid ED25519 key
                continue
            raw_public_key = public_key_der[-32:]

            # 4. Convert to hex
            public_key_hex = raw_public_key.hex()

            # Provide feedback to the user every 1000 attempts
            if count % 1000 == 0:
                print(f"    ...checked {count} keys, current key starts with {public_key_hex[:len(prefix)]}")

            # 5. Check if it matches the prefix (case-insensitive)
            if public_key_hex.startswith(prefix):
                priv_key_filename = f"{prefix.upper()}.key"
                pub_key_filename = f"{prefix.upper()}.pub"

                # Save the private key
                with open(priv_key_filename, "w") as f:
                    f.write(private_key_pem)

                # 6. For convenience, also save the public key in PEM format
                pub_pem_process = subprocess.run(
                    ["openssl", "pkey", "-pubout", "-outform", "PEM"],
                    input=private_key_pem,
                    capture_output=True,
                    check=True,
                    text=True,
                )
                with open(pub_key_filename, "w") as f:
                    f.write(pub_pem_process.stdout)

                print(f"\nSuccess! Found a key after {count} tries.")
                print(f"  Private key saved to: {priv_key_filename}")
                print(f"  Public key saved to:  {pub_key_filename}")
                print(f"  Public key (hex):   {public_key_hex}\n")
                break

        except subprocess.CalledProcessError as e:
            print(f"An error occurred with OpenSSL: {e.stderr}", file=sys.stderr)
            # Decide if you want to retry or exit
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}", file=sys.stderr)
            break


def main():
    """Main function to get user input and generate keys."""
    # Check if openssl is installed
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: OpenSSL is not found.", file=sys.stderr)
        print("Please make sure 'openssl' is installed and accessible in your system's PATH.", file=sys.stderr)
        sys.exit(1)

    print("--- ED25519 Vanity Public Key Generator ---")
    print("Generates private keys until the public key has a desired HEX prefix.")
    print("-" * 43)

    while True:
        try:
            num_prefixes_str = input("How many prefixes do you want to generate keys for? (1-4): ")
            if not num_prefixes_str:
                continue
            num_prefixes = int(num_prefixes_str)
            if 1 <= num_prefixes <= 4:
                break
            else:
                print("Invalid input. Please enter a number between 1 and 4.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    prefixes = []
    for i in range(num_prefixes):
        while True:
            prefix = input(f"Enter hexadecimal prefix #{i + 1} (e.g., F8, F8A1, FFF): ")
            if validate_hex_prefix(prefix):
                prefixes.append(prefix)
                break
            else:
                print("Invalid hexadecimal prefix. Please use only characters 0-9 and A-F.")

    print("\nStarting key generation...\n")
    for prefix in prefixes:
        generate_and_check(prefix)

if __name__ == "__main__":
    main()
