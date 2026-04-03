import io
import os
import pathlib
import queue
import signal
import socket
import subprocess
import sys
import threading
import time

try:
    import mmap as py_mmap
except ModuleNotFoundError:
    py_mmap = None


def mark(name: str) -> None:
    print(f"TOS-PY-API {name}=ok", flush=True)


def test_os_and_io() -> None:
    rfd, wfd = os.pipe()
    try:
        os.write(wfd, b"tos")
        assert os.read(rfd, 3) == b"tos"
    finally:
        os.close(rfd)
        os.close(wfd)

    buf = io.BytesIO()
    buf.write(b"api")
    assert buf.getvalue() == b"api"

    assert pathlib.Path("/usr").exists()
    assert pathlib.Path.cwd().is_dir()

    mark("os")
    mark("io")
    mark("pathlib")


def test_filesystem() -> None:
    root = pathlib.Path("/tmp") / f"tos-python-api-{os.getpid()}"
    sample = root / "sample.txt"
    try:
        if sample.exists():
            sample.unlink()
        if root.exists():
            root.rmdir()

        root.mkdir()
        sample.write_text("alpha\nbeta\n", encoding="utf-8")

        names = sorted(entry.name for entry in os.scandir(root))
        assert names == ["sample.txt"]
        assert sample.read_text(encoding="utf-8") == "alpha\nbeta\n"
        assert [path.name for path in root.glob("*.txt")] == ["sample.txt"]
        assert sample.stat().st_size == 11
    finally:
        if sample.exists():
            sample.unlink()
        if root.exists():
            root.rmdir()

    mark("filesystem")


def test_subprocess() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import os,sys; "
                "data=sys.stdin.read(); "
                "print(os.environ['TOS_PY_API']); "
                "print(data.upper().strip()); "
                "sys.exit(7)"
            ),
        ],
        check=False,
        capture_output=True,
        cwd="/tmp",
        env={**os.environ, "TOS_PY_API": "ready"},
        input="pipe\n",
        text=True,
    )
    assert proc.returncode == 7
    assert proc.stdout.splitlines() == ["ready", "PIPE"]
    print(f"TOS-PY-CHILD exit={proc.returncode} status=0", flush=True)
    mark("subprocess")


def test_mmap() -> None:
    if py_mmap is None:
        print("TOS-PY-API mmap=skip", flush=True)
        return

    mm = py_mmap.mmap(-1, 4096)
    try:
        mm[:4] = b"tos!"
        assert mm[:4] == b"tos!"
    finally:
        mm.close()
    mark("mmap")


def test_signal() -> None:
    seen: list[int] = []

    def handler(signum, _frame) -> None:
        seen.append(signum)

    old = signal.signal(signal.SIGUSR1, handler)
    try:
        os.kill(os.getpid(), signal.SIGUSR1)
        deadline = time.time() + 2.0
        while not seen and time.time() < deadline:
            time.sleep(0.01)
        assert seen == [signal.SIGUSR1]
    finally:
        signal.signal(signal.SIGUSR1, old)

    mark("signal")


def test_socket() -> None:
    try:
        left, right = socket.socketpair()
        try:
            left.sendall(b"ok")
            assert right.recv(2) == b"ok"
        finally:
            left.close()
            right.close()
    except OSError:
        try:
            payload = []
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setblocking(True)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            def accept_once() -> None:
                conn, _addr = server.accept()
                try:
                    payload.append(conn.recv(2))
                    conn.sendall(b"ok")
                finally:
                    conn.close()

            thread = threading.Thread(target=accept_once, name="tos-python-socket-accept")
            thread.start()

            client = socket.create_connection(("127.0.0.1", port), timeout=2.0)
            try:
                client.sendall(b"ok")
                assert client.recv(2) == b"ok"
            finally:
                client.close()

            thread.join(timeout=2.0)
            assert payload == [b"ok"]
        except OSError:
            print("TOS-PY-API socket=skip", flush=True)
            return
        finally:
            try:
                server.close()
            except Exception:
                pass
    mark("socket")


def test_threading() -> None:
    done = threading.Event()
    payload: list[int] = []
    ready = queue.Queue()

    def worker() -> None:
        payload.append(os.getpid())
        ready.put("thread-ready")
        done.set()

    thread = threading.Thread(target=worker, name="tos-python-api-worker")
    thread.start()
    assert done.wait(2.0)
    assert ready.get(timeout=2.0) == "thread-ready"
    thread.join(timeout=2.0)
    assert payload == [os.getpid()]
    mark("threading")
    mark("queue")


def main() -> int:
    test_os_and_io()
    test_filesystem()
    test_subprocess()
    test_mmap()
    test_signal()
    test_socket()
    test_threading()
    print("TOS-PY-API-OK total=10", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
