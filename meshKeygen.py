import sys
import os
import time
import multiprocessing
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Global flag to stop workers when a key is found
stop_event = multiprocessing.Event()

def save_key_pair(private_key, prefix_hex):
    """Saves the private and public keys to disk with secure permissions."""
    filename_base = prefix_hex.upper()
    priv_filename = f"{filename_base}.key"
    pub_filename = f"{filename_base}.pub"

    # Serialize Private Key
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize Public Key
    pub_key = private_key.public_key()
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write Private Key with restrictive permissions (600)
    fd = os.open(priv_filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(priv_bytes)

    # Write Public Key
    with open(pub_filename, "wb") as f:
        f.write(pub_bytes)

    return priv_filename, pub_filename

def worker(target_prefix, batch_size=1000):
    """
    Worker process that generates keys in a loop.
    FIX: Returns RAW BYTES instead of the Key Object to avoid PicklingErrors.
    """
    target_prefix = target_prefix.lower()
    attempts = 0
    
    while not stop_event.is_set():
        # Generate Key
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        # Get Raw Public Bytes for the vanity check
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        pub_hex = pub_bytes.hex()
        
        if pub_hex.startswith(target_prefix):
            stop_event.set() 
            
            # --- THE FIX ---
            # Export the private key to RAW BYTES so it can be sent to the main process
            raw_private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            return raw_private_bytes, pub_hex
            
        attempts += 1
        # Periodically yield control
        if attempts % batch_size == 0:
            time.sleep(0) 
            
    return None

def validate_hex_prefix(prefix):
    if not prefix: return False
    try:
        int(prefix, 16)
        return True
    except ValueError:
        return False

def main():
    print("--- High-Performance ED25519 Vanity Key Generator ---")
    print(f"    CPUs available: {multiprocessing.cpu_count()}")
    print("-" * 55)

    # 1. Get Input
    while True:
        try:
            num_prefixes_str = input("How many vanity keys to generate? (1-4): ")
            num_prefixes = int(num_prefixes_str)
            if 1 <= num_prefixes <= 4: break
            print("Please enter a number between 1 and 4.")
        except ValueError:
            pass

    prefixes = []
    for i in range(num_prefixes):
        while True:
            p = input(f"Enter hex prefix #{i + 1}: ").strip().lower()
            if validate_hex_prefix(p):
                prefixes.append(p)
                break
            print("Invalid hex string.")

    print("\nStarting generation... (Press Ctrl+C to abort)")

    # 2. Process Prefixes
    for prefix in prefixes:
        stop_event.clear()
        start_time = time.time()
        print(f"\nSearching for prefix: {prefix}...")
        
        pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
        result_async_objects = []

        try:
            # Launch workers
            for _ in range(multiprocessing.cpu_count()):
                result_async_objects.append(pool.apply_async(worker, args=(prefix,)))
            
            found_raw_priv = None
            found_hex = ""
            
            # Monitor for results
            while not stop_event.is_set():
                for res in result_async_objects:
                    if res.ready():
                        val = res.get() # This will no longer crash!
                        if val:
                            found_raw_priv, found_hex = val
                            stop_event.set()
                            break
                time.sleep(0.1)
                
            if found_raw_priv:
                duration = time.time() - start_time
                
                # Re-create the key object from the raw bytes sent by the worker
                final_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(found_raw_priv)
                
                priv_file, pub_file = save_key_pair(final_key_obj, prefix)
                
                print(f"  [SUCCESS] Found match in {duration:.2f} seconds.")
                print(f"  Public Hex: {found_hex}")
                print(f"  Saved to:   {priv_file} and {pub_file}")
            
        except KeyboardInterrupt:
            print("\nAborted by user.")
            pool.terminate()
            sys.exit(0)
        finally:
            pool.close()
            pool.join()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()