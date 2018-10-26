
import time

print(time.clock_gettime(time.CLOCK_REALTIME))
#print(time.clock_gettime(time.CLOCK_MONOTONIC))
print(time.time())
print(time.monotonic())
print(time.clock_gettime(time.CLOCK_MONOTONIC))
print(time.clock_gettime(time.CLOCK_MONOTONIC_RAW))
