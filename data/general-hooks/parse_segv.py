#!/usr/bin/python
# Examine the crash files saved by apport to attempt to determine the cause
# of a segfault.  Currently very very simplistic, and only finds commonly
# understood situations for x86/x86_64.
#
# Copyright 2009, Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
import sys, re

class ParseSegv(object):
    def __init__(self, registers, disassembly, maps, debug=False):
        self.debug = debug
        self.regs = self.parse_regs(registers)
        self.line, self.pc, self.insn, self.src, self.dest = \
            self.parse_disassembly(disassembly)
        self.maps = self.parse_maps(maps)

    def find_vma(self, addr):
        for vma in self.maps:
            if addr >= vma['start'] and addr < vma['end']:
                return vma
        return None

    def parse_maps(self, maps_str):
        maps = []
        for line in maps_str.splitlines():
            items = line.strip().split()
            try:
                span, perms, bits, dev = items[0:4]
            except:
                raise ValueError, 'Cannot parse maps line: %s' % (line.strip())
            if len(items)==5:
                name = None
            else:
                name = items[5]
            start, end = [int(x,16) for x in span.split('-')]
            maps.append({'start': start, 'end': end, 'perms': perms, 'name': name})
            if self.debug:
                print >>sys.stderr, start, end, perms, name
        return maps

    def parse_regs(self, reg_str):
        regs = dict()
        for line in reg_str.splitlines():
            reg, hexvalue = line.split()[0:2]
            regs[reg] = int(hexvalue,16)
            if self.debug:
                print >>sys.stderr, '%s:0x%08x' % (reg, regs[reg])
        return regs

    def parse_disassembly(self, disassembly):
        if not self.regs:
            raise ValueError, 'Registers not loaded yet!?'
        lines = disassembly.splitlines()
        # Throw away possible 'Dump' gdb report line
        if len(lines)>0 and lines[0].startswith('Dump'):
            lines.pop(0)
        if len(lines)<1:
            raise ValueError, 'Failed to load empty disassembly'
        line = lines[0].strip()
        if self.debug:
            print >>sys.stderr, line
        pc_str = line.split()[0]
        if pc_str.startswith('0x'):
            pc = int(pc_str.split(':')[0],16)
        else:
            # Could not identify this instruction line
            raise ValueError, 'Could not parse disassembly line: %s' % (pc_str)
        if self.debug:
            print >>sys.stderr, 'pc: 0x%08x' % (pc)

        full_insn_str = line.split(':',1)[1].strip()
        # Handle invalid memory
        if 'Cannot access memory at address' in full_insn_str or (full_insn_str == '' and len(lines)==1):
            return line, pc, None, None, None
        # Handle wrapped lines
        if full_insn_str == '' and lines[1].startswith(' '):
            line = line + ' ' + lines[1].strip()
            full_insn_str = line.split(':',1)[1].strip()

        insn_parts = full_insn_str.split()
        # Drop call target names "call   0xb7a805af <_Unwind_Find_FDE@plt+111>"
        if insn_parts[-1].endswith('>') and insn_parts[-1].startswith('<'):
            insn_parts.pop(-1)
        # Attempt to find arguments
        args_str = ''
        if len(insn_parts)>1:
            args_str = insn_parts.pop(-1)
        # Assume remainder is the insn itself
        insn = ' '.join(insn_parts)
        if self.debug:
            print >>sys.stderr, 'insn: %s' % (insn)

        args = []
        src = None
        dest = None
        if args_str == '':
            # Could not find insn args
            args = None
        else:
            if self.debug:
                print >>sys.stderr, 'args: "%s"' % (args_str)

            for m in re.finditer('([^,\(]*(\(:?[^\)]+\))*)',args_str):
                if len(m.group(0)):
                    args.append(m.group(0))
            if len(args)>0:
                src = args[0]
                if self.debug:
                    print >>sys.stderr, 'src: %s' % (src)
            if len(args)>1:
                dest = args[1]
                if self.debug:
                    print >>sys.stderr, 'dest: %s' % (dest)

        # Set up possible implicit memory destination
        if insn in ['push','pop','pushl','popl']:
            for reg in ['rsp','esp']:
                if reg in self.regs:
                    dest = '(%%%s)' % (reg)
                    break

        return line, pc, insn, src, dest

    def validate_vma(self, perm, addr, name):
        perm_name = { 'x': ['executable','executing'], 'r': ['readable','reading'], 'w': ['writable','writing'] }
        vma = self.find_vma(addr)
        if vma == None:
            alarmist = 'unknown'
            if addr < 65536:
                alarmist = 'NULL'
            return False, '%s (0x%08x) not located in a known VMA region (needed %s region)!' % (name, addr, perm_name[perm][0]), '%s %s VMA' % (perm_name[perm][1], alarmist)
        elif perm not in vma['perms']:
            alarmist = ''
            if perm == 'x':
                if 'w' in vma['perms']:
                    alarmist = 'writable '
                else:
                    alarmist = 'non-writable '
            short = '%s %sVMA %s' % (perm_name[perm][1], alarmist, vma['name'])

            return False, '%s (0x%08x) in non-%s VMA region: 0x%08x-0x%08x %s %s' % (name, addr, perm_name[perm][0], vma['start'], vma['end'], vma['perms'], vma['name']), short
        else:
            return True, '%s (0x%08x) ok' % (name, addr), '%s ok' % (perm_name[perm][1])

    def calculate_arg(self, arg):
        # Check for and pre-remove segment offset
        segment = 0
        if arg.startswith('%') and ':' in arg:
            parts = arg.split(':',1)
            segment = self.regs[parts[0][1:]]
            arg = parts[1]

        # Handle standard offsets
        parts = arg.split('(')
        offset = parts[0]
        # Handle negative signs
        sign = 1
        if offset.startswith('-'):
            sign = -1
            offset = offset[1:]
        # Skip call target dereferences
        if offset.startswith('*'):
            offset = offset[1:]
        if len(offset)>0:
            if not offset.startswith('0x'):
                raise ValueError, 'Unknown offset literal: %s' % (parts[0])
            add = int(offset[2:],16) * sign
        else:
            add = 0

        def _reg_val(self, text, val = 0):
            if text.startswith('%'):
                val = self.regs[text[1:]]
            else:
                val = int(text)
            return val

        # (%ebx, %ecx, 4) style
        value = 0
        if len(parts)>1:
            parens = parts[1][0:-1]
            reg_list = parens.split(',')

            base = 0
            if len(reg_list)>0:
                base = _reg_val(self, reg_list[0], base)
            index = 0
            if len(reg_list)>1:
                index = _reg_val(self, reg_list[1], index)
            scale = 1
            if len(reg_list)>2:
                scale = _reg_val(self, reg_list[2], scale)
            value = base + index * scale

        value = segment + value + add
        if 'esp' in self.regs:
            # 32bit
            return value % 0x100000000
        else:
            # 64bit
            return value % 0x10000000000000000

    def report(self):
        understood = False
        reason = []
        details = ['Segfault happened at: %s' % (self.line)]

        # Verify PC is in an executable region
        valid, out, short = self.validate_vma('x', self.pc, 'PC')
        details.append(out)
        if not valid:
            reason.append(short)
            understood = True

        if self.insn in ['lea','leal']:
            # Short-circuit for instructions that do not cause vma access
            details.append('insn (%s) does not access VMA' % (self.insn))
        else:
            # Verify source is readable
            if self.src:
                if not ':' in self.src and (self.src.startswith('%') or self.src.startswith('$')):
                    details.append('source "%s" ok' % (self.src))
                else:
                    addr = self.calculate_arg(self.src)
                    valid, out, short = self.validate_vma('r', addr, 'source "%s"' % (self.src))
                    details.append(out)
                    if not valid:
                        reason.append(short)
                        understood = True

            # Verify destination is writable
            if self.dest:
                if self.dest.startswith('%') and not ':' in self.dest:
                    details.append('destination "%s" ok' % (self.dest))
                else:
                    addr = self.calculate_arg(self.dest)
                    valid, out, short = self.validate_vma('w', addr, 'destination "%s"' % (self.dest))
                    details.append(out)
                    if not valid:
                        reason.append(short)
                        understood = True

        if not understood:
            reason.append('Reason could not be automatically determined.')
            details.append('Reason could not be automatically determined.')
        return understood, '\n'.join(reason), '\n'.join(details)


def add_info(report):
    # Only interested in segmentation faults...
    if report.get('Signal','0') != '11':
        return

    needed = ['Signal', 'Architecture', 'Disassembly', 'ProcMaps', 'Registers']
    for field in needed:
        if not report.has_key(field):
            report['SegvAnalysis'] = 'Skipped: missing required field "%s"' % (field)
            return

    # Only run on segv for x86 and x86_64...
    if not report['Architecture'] in ['i386','amd64']:
        return

    try:
        segv = ParseSegv(report['Registers'], report['Disassembly'], report['ProcMaps'])
        understood, reason, details = segv.report()
        if understood:
            report['SegvReason'] = reason
        report['SegvAnalysis'] = details
    except BaseException, e:
        report['SegvAnalysis'] = 'Failure: %s' % (str(e))


if __name__ == '__main__':
    if len(sys.argv)==2 and sys.argv[1] in ['-h','--help']:
        print 'To run self-test, run without any arguments (or with -v)'
        print 'To do stand-alone crash parsing:'
        print '  Usage: %s Registers.txt Disassembly.txt ProcMaps.txt' % (sys.argv[0])
        sys.exit(0)
    elif len(sys.argv)==4:
        segv = ParseSegv(file(sys.argv[1]).read(), \
                         file(sys.argv[2]).read(), \
                         file(sys.argv[3]).read())
        understood, reason, details = segv.report()
        print reason
        print ''
        print details
        rc = 0
        if not understood:
            rc = 1
        sys.exit(rc)

    else:
        import unittest, tempfile, sys

        # Default global registers, maps, and disassembly for testing
        regs = '''eax            0xffffffff -1
ecx            0xbfc6af40   -1077498048
edx            0x1  1
ebx            0x26eff4 2551796
esp            0xbfc6af24   0xbfc6af24
ebp            0xbfc6af28   0xbfc6af28
esi            0x826bb60    136756064
edi            0x8083480    134755456
eip            0x808354e    0x808354e <main+14>
eflags         0x200286 [ PF SF IF ID ]
cs             0x73 115
ss             0x7b 123
ds             0x7b 123
es             0x7b 123
fs             0x4  4
gs             0x33 51
'''
        regs64 = '''rax            0xffffffffffffffff   -1
rbx            0x26eff4 2551796
rcx            0xffffffffffffffff   -1
rdx            0xffffffffff600180   -10485376
rsi            0x0  0
rdi            0x7fffffffe3b0   140737488348080
rbp            0x0  0x0
rsp            0x7fffffffe388   0x7fffffffe388
r8             0x0  0
r9             0x0  0
r10            0x7fffffffe140   140737488347456
r11            0x246    582
r12            0x7fffffffe400   140737488348160
r13            0x7fffffffe468   140737488348264
r14            0x1  1
r15            0x7fffffffe460   140737488348256
rip            0x7ffff790be10   0x7ffff790be10 <nanosleep+16>
eflags         0x246    [ PF ZF IF ]
cs             0x33 51
ss             0x2b 43
ds             0x0  0
es             0x0  0
fs             0x0  0
gs             0x0  0
fctrl          0x37f    895
fstat          0x0  0
ftag           0xffff   65535
fiseg          0x0  0
fioff          0x40303a 4206650
foseg          0x0  0
fooff          0x0  0
fop            0x5d8    1496
mxcsr          0x1f80   [ IM DM ZM OM UM PM ]
'''
        maps = '''00110000-0026c000 r-xp 00000000 08:06 375131     /lib/tls/i686/cmov/libc-2.9.so
0026c000-0026d000 ---p 0015c000 08:06 375131     /lib/tls/i686/cmov/libc-2.9.so
0026d000-0026f000 r--p 0015c000 08:06 375131     /lib/tls/i686/cmov/libc-2.9.so
0026f000-00270000 rw-p 0015e000 08:06 375131     /lib/tls/i686/cmov/libc-2.9.so
00270000-00273000 rw-p 00000000 00:00 0 
002c1000-002e5000 r-xp 00000000 08:06 375135     /lib/tls/i686/cmov/libm-2.9.so
002e5000-002e6000 r--p 00023000 08:06 375135     /lib/tls/i686/cmov/libm-2.9.so
002e6000-002e7000 rw-p 00024000 08:06 375135     /lib/tls/i686/cmov/libm-2.9.so
00318000-00334000 r-xp 00000000 08:06 977846     /lib/ld-2.9.so
00334000-00335000 r--p 0001b000 08:06 977846     /lib/ld-2.9.so
00335000-00336000 rw-p 0001c000 08:06 977846     /lib/ld-2.9.so
0056e000-005a1000 r-xp 00000000 08:06 65575      /lib/libncurses.so.5.7
005a1000-005a3000 r--p 00033000 08:06 65575      /lib/libncurses.so.5.7
005a3000-005a4000 rw-p 00035000 08:06 65575      /lib/libncurses.so.5.7
00b67000-00b68000 r-xp 00000000 00:00 0          [vdso]
00bb6000-00bcb000 r-xp 00000000 08:06 375202     /lib/tls/i686/cmov/libpthread-2.9.so
00bcb000-00bcc000 r--p 00014000 08:06 375202     /lib/tls/i686/cmov/libpthread-2.9.so
00bcc000-00bcd000 rw-p 00015000 08:06 375202     /lib/tls/i686/cmov/libpthread-2.9.so
00bcd000-00bcf000 rw-p 00000000 00:00 0 
00beb000-00bed000 r-xp 00000000 08:06 375134     /lib/tls/i686/cmov/libdl-2.9.so
00bed000-00bee000 r--p 00001000 08:06 375134     /lib/tls/i686/cmov/libdl-2.9.so
00bee000-00bef000 rw-p 00002000 08:06 375134     /lib/tls/i686/cmov/libdl-2.9.so
00c56000-00c7a000 r-xp 00000000 08:06 1140420    /usr/lib/libexpat.so.1.5.2
00c7a000-00c7c000 r--p 00023000 08:06 1140420    /usr/lib/libexpat.so.1.5.2
00c7c000-00c7d000 rw-p 00025000 08:06 1140420    /usr/lib/libexpat.so.1.5.2
00dce000-00dfa000 r-xp 00000000 08:06 65612      /lib/libreadline.so.5.2
00dfa000-00dfb000 ---p 0002c000 08:06 65612      /lib/libreadline.so.5.2
00dfb000-00dfc000 r--p 0002c000 08:06 65612      /lib/libreadline.so.5.2
00dfc000-00dff000 rw-p 0002d000 08:06 65612      /lib/libreadline.so.5.2
00dff000-00e00000 rw-p 00000000 00:00 0 
08048000-0831c000 r-xp 00000000 08:06 1140349    /usr/bin/gdb
0831c000-0831d000 r--p 002d3000 08:06 1140349    /usr/bin/gdb
0831d000-08325000 rw-p 002d4000 08:06 1140349    /usr/bin/gdb
08325000-0833f000 rw-p 00000000 00:00 0 
b8077000-b807a000 rw-p 00000000 00:00 0 
b8096000-b8098000 rw-p 00000000 00:00 0 
bfc57000-bfc6c000 rw-p 00000000 00:00 0          [stack]
'''
        disasm = '''0x08083540 <main+0>:    lea    0x4(%esp),%ecx
0x08083544 <main+4>:    and    $0xfffffff0,%esp
0x08083547 <main+7>:    pushl  -0x4(%ecx)
0x0808354a <main+10>:   push   %ebp
0x0808354b <main+11>:   mov    %esp,%ebp
0x0808354d <main+13>:   push   %ecx
0x0808354e <main+14>:   sub    $0x14,%esp
0x08083551 <main+17>:   mov    (%ecx),%eax
0x08083553 <main+19>:   mov    0x4(%ecx),%edx
0x08083556 <main+22>:   lea    -0x14(%ebp),%ecx
0x08083559 <main+25>:   movl   $0x0,-0xc(%ebp)
0x08083560 <main+32>:   movl   $0x826bc68,-0x8(%ebp)
0x08083567 <main+39>:   mov    %eax,-0x14(%ebp)
0x0808356a <main+42>:   mov    %edx,-0x10(%ebp)
0x0808356d <main+45>:   mov    %ecx,(%esp)
0x08083570 <main+48>:   call   0x8083580 <gdb_main>
0x08083575 <main+53>:   add    $0x14,%esp
0x08083578 <main+56>:   pop    %ecx
0x08083579 <main+57>:   pop    %ebp
0x0808357a <main+58>:   lea    -0x4(%ecx),%esp
0x0808357d <main+61>:   ret    
'''

        class _TestParseSegv(unittest.TestCase):
            '''Test Segfault Parser'''

            def setUp(self):
                '''Set up prior to each test_* function'''

            def tearDown(self):
                '''Clean up after each test_* function'''

            def test_invalid_00_registers(self):
                '''Require valid registers'''

                regs = 'a 0x10\nb !!!\n'
                self.assertRaises(ValueError, ParseSegv, regs, '', '')
                try:
                    segv = ParseSegv(regs, '', '')
                except ValueError, e:
                    self.assertTrue('invalid literal for int()' in str(e), str(e))

                regs = 'a 0x10'
                disasm = '0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.regs['a'], 0x10, segv)

                segv.regs = None
                self.assertRaises(ValueError, segv.parse_disassembly, '')

            def test_invalid_01_disassembly(self):
                '''Require valid disassembly'''
                regs = 'a 0x10'

                disasm = ''
                self.assertRaises(ValueError, ParseSegv, regs, disasm, '')

                disasm = 'Dump ...'
                self.assertRaises(ValueError, ParseSegv, regs, disasm, '')

                disasm = 'Dump ...\nmonkey'
                self.assertRaises(ValueError, ParseSegv, regs, disasm, '')

                disasm = 'monkey'
                self.assertRaises(ValueError, ParseSegv, regs, disasm, '')

                disasm = '0x1111111111: Cannot access memory at address 0x1111111111\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x1111111111, segv.pc)
                self.assertEquals(segv.insn, None, segv.insn)
                self.assertEquals(segv.src, None, segv.src)
                self.assertEquals(segv.dest, None, segv.dest)

                disasm = '0x2111111111: \n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x2111111111, segv.pc)
                self.assertEquals(segv.insn, None, segv.insn)
                self.assertEquals(segv.src, None, segv.src)
                self.assertEquals(segv.dest, None, segv.dest)

                disasm = '0x8069ff0 <fopen@plt+132220>: cmpb   $0x0,(%eax,%ebx,1)\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x8069ff0, segv.pc)
                self.assertEquals(segv.insn, 'cmpb', segv.insn)
                self.assertEquals(segv.src, '$0x0', segv.src)
                self.assertEquals(segv.dest, '(%eax,%ebx,1)', segv.dest)

                disasm = '0xb765bb48 <_XSend+440>:  call   *0x40(%edi)\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0xb765bb48, segv.pc)
                self.assertEquals(segv.insn, 'call', segv.insn)
                self.assertEquals(segv.src, '*0x40(%edi)', segv.src)
                self.assertEquals(segv.dest, None, segv.dest)

                disasm = '0xb7aae5a0:   call   0xb7a805af <_Unwind_Find_FDE@plt+111>\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0xb7aae5a0, segv.pc)
                self.assertEquals(segv.insn, 'call', segv.insn)
                self.assertEquals(segv.src, '0xb7a805af', segv.src)
                self.assertEquals(segv.dest, None, segv.dest)

                disasm = '0x09083540:    mov    0x4(%esp),%es:%ecx\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x09083540, segv.pc)
                self.assertEquals(segv.insn, 'mov', segv.insn)
                self.assertEquals(segv.src, '0x4(%esp)', segv.src)
                self.assertEquals(segv.dest, '%es:%ecx', segv.dest)

                disasm = '0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x08083540, segv.pc)
                self.assertEquals(segv.insn, 'lea', segv.insn)
                self.assertEquals(segv.src, '0x4(%esp)', segv.src)
                self.assertEquals(segv.dest, '%ecx', segv.dest)

                disasm = '''0x404127 <exo_mount_hal_device_mount+167>:    
    repz cmpsb %es:(%rdi),%ds:(%rsi)\n'''
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x0404127, segv.pc)
                self.assertEquals(segv.insn, 'repz cmpsb', segv.insn)
                self.assertEquals(segv.src, '%es:(%rdi)', segv.src)
                self.assertEquals(segv.dest, '%ds:(%rsi)', segv.dest)

                disasm = '0xb031765a <hufftab16+570>: add    0x3430433,%eax'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0xb031765a, segv.pc)
                self.assertEquals(segv.insn, 'add', segv.insn)
                self.assertEquals(segv.src, '0x3430433', segv.src)
                self.assertEquals(segv.dest, '%eax', segv.dest)

                disasm = 'Dump ...\n0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x08083540, segv.pc)
                self.assertEquals(segv.insn, 'lea', segv.insn)
                self.assertEquals(segv.src, '0x4(%esp)', segv.src)
                self.assertEquals(segv.dest, '%ecx', segv.dest)

                disasm = '0x08083550 <main+0>:    nop\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x08083550, segv.pc)
                self.assertEquals(segv.insn, 'nop', segv.insn)
                self.assertEquals(segv.src, None, segv.src)
                self.assertEquals(segv.dest, None, segv.dest)

                regs = 'esp 0x444'
                disasm = '0x08083560 <main+0>:    push %ecx\n'
                segv = ParseSegv(regs, disasm, '')
                self.assertEquals(segv.pc, 0x08083560, segv.pc)
                self.assertEquals(segv.insn, 'push', segv.insn)
                self.assertEquals(segv.src, '%ecx', segv.src)
                self.assertEquals(segv.dest, '(%esp)', segv.dest)

            def test_invalid_02_maps(self):
                '''Require valid maps'''
                regs = 'a 0x10'
                disasm = 'Dump ...\n0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'

                maps = 'asdlkfjaadf'
                self.assertRaises(ValueError, ParseSegv, regs, disasm, maps)

                maps = '''005a3000-005a4000 rw-p 00035000 08:06 65575      /lib/libncurses.so.5.7
00b67000-00b68000 r-xp 00000000 00:00 0          [vdso]
00c67000-00c68000 r--p 00000000 00:00 0 '''
                segv = ParseSegv(regs, disasm, maps)
                self.assertEquals(segv.maps[0]['start'], 0x005a3000, segv)
                self.assertEquals(segv.maps[0]['end'], 0x005a4000, segv)
                self.assertEquals(segv.maps[0]['perms'], 'rw-p', segv)
                self.assertEquals(segv.maps[0]['name'], '/lib/libncurses.so.5.7', segv)

                self.assertEquals(segv.maps[1]['start'], 0x00b67000, segv)
                self.assertEquals(segv.maps[1]['end'], 0x00b68000, segv)
                self.assertEquals(segv.maps[1]['perms'], 'r-xp', segv)
                self.assertEquals(segv.maps[1]['name'], '[vdso]', segv)

                self.assertEquals(segv.maps[2]['start'], 0x00c67000, segv)
                self.assertEquals(segv.maps[2]['end'], 0x00c68000, segv)
                self.assertEquals(segv.maps[2]['perms'], 'r--p', segv)
                self.assertEquals(segv.maps[2]['name'], None, segv)

            def test_debug(self):
                '''Debug mode works'''

                regs = 'a 0x10'
                disasm = 'Dump ...\n0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'
                maps = '''005a3000-005a4000 rw-p 00035000 08:06 65575      /lib/libncurses.so.5.7
00b67000-00b68000 r-xp 00000000 00:00 0          [vdso]
00c67000-00c68000 r--p 00000000 00:00 0 '''

                sys.stderr = tempfile.NamedTemporaryFile(prefix='parse_segv-stderr-')
                segv = ParseSegv(regs, disasm, maps, debug=True)
                self.assertTrue(segv is not None, segv)

            def test_segv_unknown(self):
                '''Handles unknown segfaults'''

                disasm = '''0x08083540 <main+0>:    mov    $1,%ecx'''
                segv = ParseSegv(regs, disasm, maps)
                understood, reason, details = segv.report()
                self.assertFalse(understood, details)

                # Verify calculations
                self.assertEqual(segv.calculate_arg('(%ecx)'), 0xbfc6af40, segv.regs['ecx'])
                self.assertEqual(segv.calculate_arg('0x10(%ecx)'), 0xbfc6af50, segv.regs['ecx'])
                self.assertEqual(segv.calculate_arg('-0x20(%ecx)'), 0xbfc6af20, segv.regs['ecx'])
                self.assertEqual(segv.calculate_arg('%fs:(%ecx)'), 0xbfc6af44, segv.regs['ecx'])
                self.assertEqual(segv.calculate_arg('0x3404403'), 0x3404403, '0x3404403')
                self.assertEqual(segv.calculate_arg('*0x40(%edi)'), 0x80834c0, segv.regs['edi'])
                self.assertEqual(segv.calculate_arg('(%edx,%ebx,1)'), 0x26eff5, segv.regs['ebx'])
                self.assertEqual(segv.calculate_arg('(%eax,%ebx,1)'), 0x26eff3, segv.regs['ebx'])

                # Again, but 64bit
                disasm = '''0x08083540 <main+0>:    mov    $1,%rcx'''
                segv = ParseSegv(regs64, disasm, maps)
                understood, reason, details = segv.report()
                self.assertFalse(understood, details)

                self.assertEqual(segv.calculate_arg('(%rax,%rbx,1)'), 0x26eff3, segv.regs['rbx'])

            def test_segv_pc_missing(self):
                '''Handles PC in missing VMA'''

                disasm = '''0x00083540 <main+0>:    lea    0x4(%esp),%ecx'''
                segv = ParseSegv(regs, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('PC (0x00083540) not located in a known VMA region' in details, details)
                self.assertTrue('executing unknown VMA' in reason, reason)

                disasm = '''0x00083544:'''
                segv = ParseSegv(regs, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('PC (0x00083544) not located in a known VMA region' in details, details)
                self.assertTrue('executing unknown VMA' in reason, reason)

            def test_segv_pc_null(self):
                '''Handles PC in NULL VMA'''

                disasm = '''0x00000540 <main+0>:    lea    0x4(%esp),%ecx'''
                segv = ParseSegv(regs, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('PC (0x00000540) not located in a known VMA region' in details, details)
                self.assertTrue('executing NULL VMA' in reason, reason)

            def test_segv_pc_nx_writable(self):
                '''Handles PC in writable NX VMA'''

                disasm = '''0x005a3000 <main+0>:    lea    0x4(%esp),%ecx'''
                segv = ParseSegv(regs, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('PC (0x005a3000) in non-executable VMA region:' in details, details)
                self.assertTrue('executing writable VMA /lib/libncurses.so.5.7' in reason, reason)

            def test_segv_pc_nx_unwritable(self):
                '''Handles PC in non-writable NX VMA'''

                disasm = '''0x00dfb000 <main+0>:    lea    0x4(%esp),%ecx'''
                segv = ParseSegv(regs, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('PC (0x00dfb000) in non-executable VMA region:' in details, details)
                self.assertTrue('executing non-writable VMA /lib/libreadline.so.5.2' in reason, reason)

            def test_segv_src_missing(self):
                '''Handles source in missing VMA'''

                reg = regs + 'ecx            0x0006af24   0xbfc6af24'
                disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

                segv = ParseSegv(reg, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('source "-0x4(%ecx)" (0x0006af20) not located in a known VMA region' in details, details)
                self.assertTrue('reading unknown VMA' in reason, reason)

            def test_segv_src_null(self):
                '''Handles source in NULL VMA'''

                reg = regs + 'ecx            0x00000024   0xbfc6af24'
                disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

                segv = ParseSegv(reg, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('source "-0x4(%ecx)" (0x00000020) not located in a known VMA region' in details, details)
                self.assertTrue('reading NULL VMA' in reason, reason)

            def test_segv_src_not_readable(self):
                '''Handles source not in readable VMA'''

                reg = regs + 'ecx            0x0026c080   0xbfc6af24'
                disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'
                segv = ParseSegv(reg, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('source "-0x4(%ecx)" (0x0026c07c) in non-readable VMA region:' in details, details)
                self.assertTrue('reading VMA /lib/tls/i686/cmov/libc-2.9.so' in reason, reason)

            def test_segv_dest_missing(self):
                '''Handles destintation in missing VMA'''

                reg = regs + 'esp            0x0006af24   0xbfc6af24'
                disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

                segv = ParseSegv(reg, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('destination "(%esp)" (0x0006af24) not located in a known VMA region' in details, details)
                self.assertTrue('writing unknown VMA' in reason, reason)

            def test_segv_dest_null(self):
                '''Handles destintation in NULL VMA'''

                reg = regs + 'esp            0x00000024   0xbfc6af24'
                disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

                segv = ParseSegv(reg, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('destination "(%esp)" (0x00000024) not located in a known VMA region' in details, details)
                self.assertTrue('writing NULL VMA' in reason, reason)

            def test_segv_dest_not_writable(self):
                '''Handles destination not in writable VMA'''

                reg = regs + 'esp            0x08048080   0xbfc6af24'
                disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'
                segv = ParseSegv(reg, disasm, maps)
                understood, reason, details = segv.report()
                self.assertTrue(understood, details)
                self.assertTrue('destination "(%esp)" (0x08048080) in non-writable VMA region:' in details, details)
                self.assertTrue('writing VMA /usr/bin/gdb' in reason, reason)

            def test_segv_crackful_disasm(self):
                '''Rejects insane disassemblies'''

                disasm = '0x08083547 <main+7>:    pushl  -0x4(blah)'
                segv = ParseSegv(regs, disasm, maps)
                self.assertRaises(ValueError, segv.report)

                disasm = '0x08083547 <main+7>:    pushl  -04(%ecx)'
                segv = ParseSegv(regs, disasm, maps)
                self.assertRaises(ValueError, segv.report)

    unittest.main()
