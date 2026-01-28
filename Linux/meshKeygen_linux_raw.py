import sys
import os
import time
import multiprocessing
import ctypes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def init_worker(counter, stop_event):
    global _worker_counter, _worker_stop_event
    _worker_counter = counter
    _worker_stop_event = stop_event

def save_raw_hex(prefix_hex, priv_hex, pub_hex):
    """Saves the keys as plain hex strings in a .txt file."""
    filename = f"{prefix_hex.upper()}_raw.txt"
    content = (
        f"Prefix Searched: {prefix_hex}\n"
        f"Public Key (Hex):  {pub_hex}\n"
        f"Private Key (Hex): {priv_hex}\n"
    )
    # Secure permissions for the text file
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    return filename

def worker(target_prefix, batch_size=1000):
    global _worker_counter, _worker_stop_event
    target_prefix = target_prefix.lower()
    local_attempts = 0
    
    while not _worker_stop_event.is_set():
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        # Get raw bytes
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pub_hex = pub_bytes.hex()
        
        if pub_hex.startswith(target_prefix):
            _worker_stop_event.set() 
            # Get private bytes for the result
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            return priv_bytes.hex(), pub_hex
            
        local_attempts += 1
        if local_attempts >= batch_size:
            with _worker_counter.get_lock():
                _worker_counter.value += local_attempts
            local_attempts = 0
    return None

def main():
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except RuntimeError:
        pass

    print("\n" + "="*50)
    print("   ED25519 VANITY GENERATOR (RAW HEX MODE)")
    print("="*50, flush=True)

    cpus = multiprocessing.cpu_count()
    stop_event = multiprocessing.Event()
    total_attempts = multiprocessing.Value(ctypes.c_ulonglong, 0)

    prefix = input("Enter hex prefix to find: ").strip().lower()
    if not all(c in "0123456789abcdef" for c in prefix):
        print("Error: Invalid hex characters.")
        return

    start_time = time.time()
    pool = multiprocessing.Pool(processes=cpus, initializer=init_worker, initargs=(total_attempts, stop_event))
    async_results = [pool.apply_async(worker, args=(prefix,)) for _ in range(cpus)]
    
    found_data = None
    try:
        while found_data is None:
            elapsed = time.time() - start_time
            current_total = total_attempts.value
            h_s = current_total / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\rSpeed: {h_s:,.0f} keys/s | Checked: {current_total:,} ")
            sys.stdout.flush()
            
            for res in async_results:
                if res.ready():
                    found_data = res.get()
                    if found_data: break
            time.sleep(0.1)
            
        priv_hex, pub_hex = found_data
        txt_file = save_raw_hex(prefix, priv_hex, pub_hex)
        
        print(f"\n\n[SUCCESS] Match Found!")
        print(f"Target Prefix: {prefix}")
        print(f"Public Hex:    {pub_hex}")
        print(f"Private Hex:   {priv_hex}")
        print(f"Saved to:      {txt_file}")
        
    except KeyboardInterrupt:
        print("\nAborted.")
    finally:
        pool.terminate()
        pool.join()

if __name__ == "__main__":
    main()
