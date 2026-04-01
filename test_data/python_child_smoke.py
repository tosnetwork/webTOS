import os
import sys

rfd, wfd = os.pipe()
pid = os.fork()

if pid == 0:
    try:
        os.close(rfd)
        os.close(wfd)
        os.execv(sys.executable, [sys.executable, "-u", "-c", "import sys; sys.exit(7)"])
    except BaseException:
        os._exit(127)

os.close(rfd)
os.close(wfd)

_, status = os.waitpid(pid, 0)
child_exit = os.waitstatus_to_exitcode(status)
ok = child_exit == 7
print(f"TOS-PY-CHILD exit={child_exit} status={0 if ok else 1}", flush=True)
sys.exit(0 if ok else 1)
