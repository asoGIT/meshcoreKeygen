import sys
import os
import time
import multiprocessing
import ctypes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# --- WORKER UTILITIES ---
def init_worker(counter, stop_event):
    global _worker_counter, _worker_stop_event
    _worker_counter = counter
    _worker_stop_event = stop_event

def save_key_pair(private_key_obj, prefix_hex):
    filename_base = prefix_hex.upper()
    priv_filename = f"{filename_base}.key"
    pub_filename = f"{filename_base}.pub"

    priv_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fd = os.open(priv_filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(priv_bytes)
    with open(pub_filename, "wb") as f:
        f.write(pub_bytes)

    return priv_filename, pub_filename

def worker(target_prefix, batch_size=1000):
    global _worker_counter, _worker_stop_event
    target_prefix = target_prefix.lower()
    local_attempts = 0
    
    while not _worker_stop_event.is_set():
        private_key = ed25519.Ed25519PrivateKey.generate()
        pub_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        
        if pub_hex.startswith(target_prefix):
            _worker_stop_event.set() 
            with _worker_counter.get_lock():
                _worker_counter.value += local_attempts
            
            return private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ), pub_hex
            
        local_attempts += 1
        if local_attempts >= batch_size:
            with _worker_counter.get_lock():
                _worker_counter.value += local_attempts
            local_attempts = 0
    return None

# --- MAIN EXECUTION ---
def main():
    # Force spawn for Arch Linux stability
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except RuntimeError:
        pass

    print("\n" + "="*50)
    print("   ED25519 VANITY GENERATOR")
    print("="*50, flush=True)

    cpus = multiprocessing.cpu_count()
    stop_event = multiprocessing.Event()
    total_attempts = multiprocessing.Value(ctypes.c_ulonglong, 0)

    # 1. Ask for Number of Keys
    while True:
        try:
            num_in = input("How many unique prefixes to find? (1-4): ")
            num_prefixes = int(num_in)
            if 1 <= num_prefixes <= 4: break
            print("Please choose between 1 and 4.")
        except ValueError:
            print("Invalid input. Enter a number.")

    # 2. Collect Prefixes
    prefixes = []
    for i in range(num_prefixes):
        while True:
            p = input(f"Enter hex prefix #{i+1}: ").strip().lower()
            if p and all(c in "0123456789abcdef" for c in p):
                prefixes.append(p)
                break
            print("Invalid hex! Use 0-9 and a-f only.")

    # 3. Process each prefix
    for prefix in prefixes:
        stop_event.clear()
        with total_attempts.get_lock():
            total_attempts.value = 0
            
        print(f"\nSearching for: {prefix} using {cpus} cores...")
        start_time = time.time()
        
        pool = multiprocessing.Pool(
            processes=cpus, 
            initializer=init_worker, 
            initargs=(total_attempts, stop_event)
        )
        
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
                
                if stop_event.is_set() and found_data is None:
                    time.sleep(0.05)
                time.sleep(0.1)
                
            raw_priv, found_hex = found_data
            duration = time.time() - start_time
            key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
            priv_f, pub_f = save_key_pair(key_obj, prefix)
            
            print(f"\n\n[SUCCESS] Match: {found_hex}")
            print(f"Time: {duration:.4f}s | Files: {priv_f}, {pub_f}")
            
        except KeyboardInterrupt:
            print("\n\nUser aborted.")
            pool.terminate()
            sys.exit(0)
        finally:
            pool.close()
            pool.join()

    print("\nAll tasks finished. Enjoy your new keys!", flush=True)

if __name__ == "__main__":
    main()
