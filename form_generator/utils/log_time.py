import time

def log_time(label, start_time):
    elapsed = time.time() - start_time
    print(f"{label:<30}  : {elapsed:.3f} sec")
