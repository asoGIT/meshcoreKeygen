import sys
import os
import time
import multiprocessing
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# 1. Simple worker with NO shared memory (just to see if it works)
def worker(prefix):
    # Print immediately so we know the worker is alive
    print(f"\n[Worker {os.getpid()}] Started searching for {prefix}...", flush=True)
    
    count = 0
    while True:
        # Generate key
        private_key = ed25519.Ed25519PrivateKey.generate()
        pub_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

        if pub_hex.startswith(prefix):
            print(f"\n[Worker {os.getpid()}] FOUND MATCH!", flush=True)
            return pub_hex
        
        count += 1
        if count % 10000 == 0:
            # Print a heartbeat every 10k keys
            print(f".", end="", flush=True)

def main():
    # Force 'spawn' method for clean start on Linux
    try:
        multiprocessing.set_start_method('spawn', force=True)
    except Exception as e:
        print(f"Start method error: {e}", flush=True)

    print("--- DIAGNOSTIC STARTUP ---", flush=True)
    
    # Check if cryptography is working
    try:
        test_key = ed25519.Ed25519PrivateKey.generate()
        print("Cryptography library: OK", flush=True)
    except Exception as e:
        print(f"Cryptography failure: {e}", flush=True)
        return

    prefix = input("Enter a 1-character prefix to test (e.g., 'a'): ").strip().lower()
    
    cpus = multiprocessing.cpu_count()
    print(f"Starting {cpus} workers...", flush=True)

    # Use a simple Pool without Manager or complex shared values
    pool = multiprocessing.Pool(processes=cpus)
    
    try:
        # Start only one worker first to see if it responds
        result = pool.apply_async(worker, args=(prefix,))
        
        print("Waiting for worker response... (You should see dots appearing)", flush=True)
        
        # Wait for the result with a timeout
        output = result.get(timeout=60) 
        print(f"\nMain process received: {output}", flush=True)

    except KeyboardInterrupt:
        print("\nInterrupted.", flush=True)
    except multiprocessing.TimeoutError:
        print("\nError: Worker timed out. It's not communicating back.", flush=True)
    except Exception as e:
        print(f"\nError: {e}", flush=True)
    finally:
        pool.terminate()
        pool.join()

if __name__ == "__main__":
    main()
