import cProfile
import pstats
import io
import time
from pathlib import Path
import sys

# Ensure project root is in path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from carving.engine import CarvingEngine
from carving.registry import SignatureRegistry
from disk.reader import DiskReader
from recovery.engine import RecoveryStats

def profile_scan():
    print("Initializing profiling scan on test_50mb.img...")
    
    registry = SignatureRegistry()
    registry.register_builtins()
    
    reader = DiskReader("test_50mb.img")
    stats = RecoveryStats()
    
    engine = CarvingEngine(
        registry=registry,
        output_dir="test_carve_out",
        progress_callback=lambda cur, total, files: True
    )
    
    pr = cProfile.Profile()
    pr.enable()
    
    start_time = time.perf_counter()
    engine.carve(reader)
    elapsed = time.perf_counter() - start_time
    
    pr.disable()
    
    total_bytes = 50 * 1024 * 1024
    mb_per_sec = (total_bytes / 1024 / 1024) / elapsed
    
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats(30)
    
    print(f"\n--- PERFORMANCE RESULTS ---")
    print(f"Elapsed Time: {elapsed:.2f} s")
    print(f"Throughput:   {mb_per_sec:.2f} MB/s")
    print(f"\n--- TOP 30 FUNCTIONS ---")
    print(s.getvalue())

if __name__ == "__main__":
    profile_scan()
