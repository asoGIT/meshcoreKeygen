import sys
import os
import time
import multiprocessing
import ctypes
import csv
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def init_worker(counter):
    global _worker_counter
    _worker_counter = counter

def save_to_csv(prefix, pub_hex, priv_hex):
    """Appends found keys to a CSV file."""
    file_exists = os.path.isfile("found_keys.csv")
    with open("found_keys.csv", "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Target Prefix", "Public Hex", "Private Hex"])
        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), prefix, pub_hex, priv_hex])

def worker(target_prefix, batch_size=2000):
    global _worker_counter
    target_prefix = target_prefix.lower()
    local_attempts = 0
    
    while True:
        private_key = ed25519.Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pub_hex = pub_bytes.hex()
        
        if pub_hex.startswith(target_prefix):
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Update counter before returning result
            with _worker_counter.get_lock():
                _worker_counter.value += local_attempts
            return priv_bytes.hex(), pub_hex
            
        local_attempts += 1
        if local_attempts >= batch_size:
            with _worker_counter.get_lock():
                _worker_counter.value += local_attempts
            local_attempts = 0

def main():
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except RuntimeError:
        pass

    print("\n" + "="*50)
    print("   ED25519 BULK VANITY GENERATOR")
    print("   (Press Ctrl+C to stop)")
    print("="*50, flush=True)

    cpus = multiprocessing.cpu_count()
    total_attempts = multiprocessing.Value(ctypes.c_ulonglong, 0)
    
    prefix = input("Enter hex prefix to hunt for: ").strip().lower()
    if not all(c in "0123456789abcdef" for c in prefix):
        print("Error: Invalid hex.")
        return

    print(f"\nHunting started... Results will be saved to 'found_keys.csv'")
    start_time = time.time()
    found_count = 0

    try:
        while True:
            # Create a fresh pool for the next search
            # This ensures we catch results cleanly in Bulk Mode
            with multiprocessing.Pool(processes=cpus, initializer=init_worker, initargs=(total_attempts,)) as pool:
                # We use apply_async but we only need ONE result to trigger a save
                # then we loop again to keep hunting
                result_objects = [pool.apply_async(worker, args=(prefix,)) for _ in range(cpus)]
                
                match_found = False
                while not match_found:
                    elapsed = time.time() - start_time
                    current_total = total_attempts.value
                    h_s = current_total / elapsed if elapsed > 0 else 0
                    
                    sys.stdout.write(f"\rSpeed: {h_s:,.0f} keys/s | Found: {found_count} | Checked: {current_total:,}")
                    sys.stdout.flush()
                    
                    for res in result_objects:
                        if res.ready():
                            priv_h, pub_h = res.get()
                            save_to_csv(prefix, pub_h, priv_h)
                            found_count += 1
                            match_found = True
                            break
                    time.sleep(0.1)
                
                # Close the pool to reset for the next hunt
                pool.terminate()

    except KeyboardInterrupt:
        print(f"\n\nStopped. Total keys found: {found_count}")
    
if __name__ == "__main__":
    main()
