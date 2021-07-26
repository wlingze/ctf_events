#!/usr/bin/env python
import os, sys, ctypes, resource, platform, stat
from collections import OrderedDict
try:
    integer_types = int, long
except NameError:
    integer_types = int,
exe   = 'true'
argv  = [bytes(a) for a in [bytearray(b'true')]]
env   = None

os.chdir('.')

if env is not None:
    env = OrderedDict((bytes(k), bytes(v)) for k,v in env)
    os.environ.clear()
    getattr(os, 'environb', os.environ).update(env)
else:
    env = os.environ

def is_exe(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)

PATH = os.environ.get('PATH','').split(os.pathsep)

if os.path.sep not in exe and not is_exe(exe):
    for path in PATH:
        test_path = os.path.join(path, exe)
        if is_exe(test_path):
            exe = test_path
            break

if not is_exe(exe):
    sys.stderr.write('3\n')
    sys.stderr.write("{} is not executable or does not exist in $PATH: {}".format(exe,PATH))
    sys.exit(-1)

if not True:
    PR_SET_NO_NEW_PRIVS = 38
    result = ctypes.CDLL('libc.so.6').prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    if result != 0:
        sys.stdout.write('3\n')
        sys.stdout.write("Could not disable setuid: prctl(PR_SET_NO_NEW_PRIVS) failed")
        sys.exit(-1)

try:
    PR_SET_PTRACER = 0x59616d61
    PR_SET_PTRACER_ANY = -1
    ctypes.CDLL('libc.so.6').prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
except Exception:
    pass

# Determine what UID the process will execute as
# This is used for locating apport core dumps
suid = os.getuid()
sgid = os.getgid()
st = os.stat(exe)
if True:
    if (st.st_mode & stat.S_ISUID):
        suid = st.st_uid
    if (st.st_mode & stat.S_ISGID):
        sgid = st.st_gid

if sys.argv[-1] == 'check':
    sys.stdout.write("1\n")
    sys.stdout.write(str(os.getpid()) + "\n")
    sys.stdout.write(str(os.getuid()) + "\n")
    sys.stdout.write(str(os.getgid()) + "\n")
    sys.stdout.write(str(suid) + "\n")
    sys.stdout.write(str(sgid) + "\n")
    sys.stdout.write(os.path.realpath(exe) + '\x00')
    sys.stdout.flush()

for fd, newfd in {0: 0, 1: 1, 2:2}.items():
    if newfd is None:
        os.close(fd)
    elif isinstance(newfd, (str, bytes)):
        newfd = os.open(newfd, os.O_RDONLY if fd == 0 else (os.O_RDWR|os.O_CREAT))
        os.dup2(newfd, fd)
        os.close(newfd)
    elif isinstance(newfd, integer_types) and newfd != fd:
        os.dup2(fd, newfd)

if not True:
    if platform.system().lower() == 'linux' and True is not True:
        ADDR_NO_RANDOMIZE = 0x0040000
        ctypes.CDLL('libc.so.6').personality(ADDR_NO_RANDOMIZE)

    resource.setrlimit(resource.RLIMIT_STACK, (-1, -1))

# Attempt to dump ALL core file regions
try:
    with open('/proc/self/coredump_filter', 'w') as core_filter:
        core_filter.write('0x3f\n')
except Exception:
    pass

# Assume that the user would prefer to have core dumps.
try:
    resource.setrlimit(resource.RLIMIT_CORE, (-1, -1))
except Exception:
    pass

def preexec():
            import platform
            print('\n'.join(platform.uname()))
preexec(*())

os.execve(exe, argv, env)
