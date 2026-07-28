"""
Simple benchmark to measure sign/verify performance.
"""
import time
from key_utils import generate_keys
from crypto_utils import sign_message, verify_message

def test_benchmark_print():
    priv, pub = generate_keys(2048)
    msg = b"x" * 1024
    t0 = time.time()
    container = sign_message(msg, priv)
    t1 = time.time()
    ok = verify_message(msg, pub, container)
    t2 = time.time()
    print("sign_time_ms:", (t1 - t0) * 1000)
    print("verify_time_ms:", (t2 - t1) * 1000)
    assert ok is True
