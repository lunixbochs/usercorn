import os
import re

CONFIG = [
    ('darwin_x86.h',   'Darwin_x86',   'darwin_x86_sys.go'),
    ('linux_arm.h',    'Linux_arm',    'linux_arm_sys.go'),
    ('linux_mips.h',    'Linux_mips',  'linux_mips_sys.go'),
    ('linux_x86.h',    'Linux_x86',    'linux_x86_sys.go'),
    ('linux_x86_64.h', 'Linux_x86_64', 'linux_x86_64_sys.go'),
]
TARGET = '../go/syscalls/gen/'
SRC = 'syscalls'

FILE_TEMPLATE = '''
package gen

var %(cls)s = map[int]string{
\t%(lines)s
}
'''.lstrip()

LINE_TEMPLATE = '%(num)s "%(name)s",'

define_re = re.compile(r'^#define\s+(?P<name>\w+)\s*\(?\s*(?P<value>\d+)\s*\)?$')
sys_re = re.compile(r'^#define\s+(SYS|__NR)_(?P<name>[a-z0-9_]+)\s*(?P<value>\(\s*[\w\+\s]+\s*\)|\d+)$')

base = os.path.dirname(__file__)
if base:
    os.chdir(base)

for header, cls, target in CONFIG:
    header = os.path.join(SRC, header)
    target = os.path.join(TARGET, target)
    syscalls = []
    defines = {}
    with open(header) as f:
        for line in f:
            line = line.strip()
            match = sys_re.match(line)
            if match:
                value = match.group('value')
                if not value.isdigit():
                    for k, v in defines.items():
                        value = value.replace(k, v)
                    value = eval(value)
                syscalls.append((match.group('name'), value))
            else:
                match = define_re.match(line)
                if match:
                    defines[match.group('name')] = match.group('value')

    num_len = max(len(str(num)) for name, num in syscalls) + 1
    lines = []
    for name, num in syscalls:
        num = (str(num) + ':').ljust(num_len)
        lines.append(LINE_TEMPLATE % {'name': name, 'num': num})

    with open(target, 'w') as f:
        f.write(FILE_TEMPLATE % {'cls': cls, 'lines': '\n\t'.join(lines)})
