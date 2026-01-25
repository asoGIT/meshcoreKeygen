import sys
import os
import time
import multiprocessing
import ctypes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Global variables for workers
stop_event = multiprocessing.Event()
# This will be initialized in each worker process
_worker_counter = None

def init_worker(counter):
    """Initializes the global counter in each worker process."""
    global _worker_counter
    _worker_counter = counter

def save_key_pair(private_key, prefix_hex):
    """Saves the private and public keys to disk."""
    filename_base = prefix_hex.upper()
    priv_filename = f"{filename_base}.key"
    pub_filename = f"{filename_base}.pub"

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_key = private_key.public_key()
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Secure file creation (mode 600)
    fd = os.open(priv_filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(priv_bytes)

    with open(pub_filename, "wb") as f:
        f.write(pub_bytes)

    return priv_filename, pub_filename

def worker(target_prefix, batch_size=2000):
    """Worker process logic."""
    global _worker_counter
    target_prefix = target_prefix.lower()
    local_attempts = 0
    
    while not stop_event.is_set():
        private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        pub_hex = pub_bytes.hex()
        
        if pub_hex.startswith(target_prefix):
            stop_event.set() 
            # Final update to global counter
            with _worker_counter.get_lock():
                _worker_counter.value += local_attempts
            
            raw_private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            return raw_private_bytes, pub_hex
            
        local_attempts += 1
        
        # Batch update to shared memory to keep speed high
        if local_attempts >= batch_size:
            with _worker_counter.get_lock():
                _worker_counter.value += local_attempts
            local_attempts = 0
            
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
    cpus = multiprocessing.cpu_count()
    print(f"    CPUs available: {cpus}")
    print("-" * 55)

    # Use a thread-safe shared Value
    total_attempts = multiprocessing.Value(ctypes.c_ulonglong, 0)

    while True:
        try:
            num_in = input("How many vanity keys to generate? (1-4): ")
            num_prefixes = int(num_in)
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

    for prefix in prefixes:
        stop_event.clear()
        with total_attempts.get_lock():
            total_attempts.value = 0
            
        start_time = time.time()
        print(f"\nSearching for prefix: {prefix}...")
        
        # THE FIX: initializer attaches total_attempts to each worker on creation
        pool = multiprocessing.Pool(
            processes=cpus, 
            initializer=init_worker, 
            initargs=(total_attempts,)
        )
        
        result_async_objects = []

        try:
            for _ in range(cpus):
                result_async_objects.append(pool.apply_async(worker, args=(prefix,)))
            
            found_raw_priv = None
            found_hex = ""
            
            while not stop_event.is_set():
                elapsed = time.time() - start_time
                current_total = total_attempts.value
                
                h_s = current_total / elapsed if elapsed > 0 else 0
                # Using \r to rewrite the line and :.2f for the hash rate
                sys.stdout.write(f"\rSpeed: {h_s:,.0f} keys/s | Total checked: {current_total:,}")
                sys.stdout.flush()
                
                for res in result_async_objects:
                    if res.ready():
                        val = res.get()
                        if val:
                            found_raw_priv, found_hex = val
                            stop_event.set()
                            break
                time.sleep(0.4)
                
            if found_raw_priv:
                duration = time.time() - start_time
                final_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(found_raw_priv)
                priv_file, pub_file = save_key_pair(final_key_obj, prefix)
                
                print(f"\n\n  [SUCCESS] Found match in {duration:.2f} seconds.")
                print(f"  Final Speed: {total_attempts.value / duration:,.0f} keys/s")
                print(f"  Public Hex: {found_hex}")
                print(f"  Files: {priv_file}, {pub_file}\n")
            
        except KeyboardInterrupt:
            print("\n\nAborted by user.")
            pool.terminate()
            sys.exit(0)
        finally:
            pool.close()
            pool.join()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()