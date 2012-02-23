import unittest, tempfile, sys, os.path

# find module in local tree
rootdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(rootdir, 'data', 'general-hooks'))

import parse_segv

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
rsp            0x0000bfc6af24   0x0000bfc6af24
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

class T(unittest.TestCase):
    '''Test Segfault Parser'''

    def test_invalid_00_registers(self):
        '''Require valid registers'''

        regs = 'a 0x10\nb !!!\n'
        self.assertRaises(ValueError, parse_segv.ParseSegv, regs, '', '')
        try:
            segv = parse_segv.ParseSegv(regs, '', '')
        except ValueError as e:
            self.assertTrue('invalid literal for int()' in str(e), str(e))

        regs = 'a 0x10'
        disasm = '0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.regs['a'], 0x10, segv)

        segv.regs = None
        self.assertRaises(ValueError, segv.parse_disassembly, '')

    def test_invalid_01_disassembly(self):
        '''Require valid disassembly'''
        regs = 'a 0x10'

        disasm = ''
        self.assertRaises(ValueError, parse_segv.ParseSegv, regs, disasm, '')

        disasm = 'Dump ...'
        self.assertRaises(ValueError, parse_segv.ParseSegv, regs, disasm, '')

        disasm = 'Dump ...\nmonkey'
        self.assertRaises(ValueError, parse_segv.ParseSegv, regs, disasm, '')

        disasm = 'monkey'
        self.assertRaises(ValueError, parse_segv.ParseSegv, regs, disasm, '')

        disasm = '0x1111111111: Cannot access memory at address 0x1111111111\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x1111111111, segv.pc)
        self.assertEquals(segv.insn, None, segv.insn)
        self.assertEquals(segv.src, None, segv.src)
        self.assertEquals(segv.dest, None, segv.dest)

        disasm = '0x2111111111: \n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x2111111111, segv.pc)
        self.assertEquals(segv.insn, None, segv.insn)
        self.assertEquals(segv.src, None, segv.src)
        self.assertEquals(segv.dest, None, segv.dest)

        disasm = '0x8069ff0 <fopen@plt+132220>: cmpb   $0x0,(%eax,%ebx,1)\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x8069ff0, segv.pc)
        self.assertEquals(segv.insn, 'cmpb', segv.insn)
        self.assertEquals(segv.src, '$0x0', segv.src)
        self.assertEquals(segv.dest, '(%eax,%ebx,1)', segv.dest)

        disasm = '0xb765bb48 <_XSend+440>:  call   *0x40(%edi)\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0xb765bb48, segv.pc)
        self.assertEquals(segv.insn, 'call', segv.insn)
        self.assertEquals(segv.src, '*0x40(%edi)', segv.src)
        self.assertEquals(segv.dest, None, segv.dest)

        disasm = '0xb7aae5a0:   call   0xb7a805af <_Unwind_Find_FDE@plt+111>\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0xb7aae5a0, segv.pc)
        self.assertEquals(segv.insn, 'call', segv.insn)
        self.assertEquals(segv.src, '0xb7a805af', segv.src)
        self.assertEquals(segv.dest, None, segv.dest)

        disasm = '0x09083540:    mov    0x4(%esp),%es:%ecx\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x09083540, segv.pc)
        self.assertEquals(segv.insn, 'mov', segv.insn)
        self.assertEquals(segv.src, '0x4(%esp)', segv.src)
        self.assertEquals(segv.dest, '%es:%ecx', segv.dest)

        disasm = '0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x08083540, segv.pc)
        self.assertEquals(segv.insn, 'lea', segv.insn)
        self.assertEquals(segv.src, '0x4(%esp)', segv.src)
        self.assertEquals(segv.dest, '%ecx', segv.dest)

        disasm = '''0x404127 <exo_mount_hal_device_mount+167>:    
    repz cmpsb %es:(%rdi),%ds:(%rsi)\n'''
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x0404127, segv.pc)
        self.assertEquals(segv.insn, 'repz cmpsb', segv.insn)
        self.assertEquals(segv.src, '%es:(%rdi)', segv.src)
        self.assertEquals(segv.dest, '%ds:(%rsi)', segv.dest)

        disasm = '0xb031765a <hufftab16+570>: add    0x3430433,%eax'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0xb031765a, segv.pc)
        self.assertEquals(segv.insn, 'add', segv.insn)
        self.assertEquals(segv.src, '0x3430433', segv.src)
        self.assertEquals(segv.dest, '%eax', segv.dest)

        disasm = 'Dump ...\n0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x08083540, segv.pc)
        self.assertEquals(segv.insn, 'lea', segv.insn)
        self.assertEquals(segv.src, '0x4(%esp)', segv.src)
        self.assertEquals(segv.dest, '%ecx', segv.dest)

        disasm = '0x08083550 <main+0>:    nop\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x08083550, segv.pc)
        self.assertEquals(segv.insn, 'nop', segv.insn)
        self.assertEquals(segv.src, None, segv.src)
        self.assertEquals(segv.dest, None, segv.dest)

        regs = 'esp 0x444'
        disasm = '0x08083560 <main+0>:    push %ecx\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x08083560, segv.pc)
        self.assertEquals(segv.insn, 'push', segv.insn)
        self.assertEquals(segv.src, '%ecx', segv.src)
        self.assertEquals(segv.dest, '(%esp)', segv.dest)

        # GDB 7.1
        regs = 'esp 0x444'
        disasm = '=> 0x08083560 <main+0>:    push %ecx\n'
        segv = parse_segv.ParseSegv(regs, disasm, '')
        self.assertEquals(segv.pc, 0x08083560, segv.pc)
        self.assertEquals(segv.insn, 'push', segv.insn)
        self.assertEquals(segv.src, '%ecx', segv.src)
        self.assertEquals(segv.dest, '(%esp)', segv.dest)

    def test_ioport_operation(self):
        '''I/O port violations'''

        regs = 'rax            0x3  3'
        disasm = '''0x4087f1 <snd_pcm_hw_params_set_channels_near@plt+19345>:   
    out    %al,$0xb3
'''
        maps = '''00400000-00412000 r-xp 00000000 08:04 10371157                           /usr/sbin/pommed
00611000-00614000 rw-p 00011000 08:04 10371157                           /usr/sbin/pommed
00614000-00635000 rw-p 00614000 00:00 0                                  [heap]
'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        self.assertEquals(segv.pc, 0x4087f1, segv.pc)
        self.assertEquals(segv.insn, 'out', segv.insn)
        self.assertEquals(segv.src, '%al', segv.src)
        self.assertEquals(segv.dest, '$0xb3', segv.dest)

        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('disallowed I/O port operation on port 3' in reason, reason)

    def test_invalid_02_maps(self):
        '''Require valid maps'''
        regs = 'a 0x10'
        disasm = 'Dump ...\n0x08083540 <main+0>:    lea    0x4(%esp),%ecx\n'

        maps = 'asdlkfjaadf'
        self.assertRaises(ValueError, parse_segv.ParseSegv, regs, disasm, maps)

        maps = '''005a3000-005a4000 rw-p 00035000 08:06 65575      /lib/libncurses.so.5.7
00b67000-00b68000 r-xp 00000000 00:00 0          [vdso]
00c67000-00c68000 r--p 00000000 00:00 0 '''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
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
        segv = parse_segv.ParseSegv(regs, disasm, maps, debug=True)
        self.assertTrue(segv is not None, segv)

    def test_register_values(self):
        '''Sub-register parsing'''

        disasm = '''0x08083540 <main+0>:    mov    $1,%ecx'''
        segv = parse_segv.ParseSegv(regs64, disasm, '')

        val = segv.register_value('%rdx')
        self.assertEqual(val, 0xffffffffff600180, hex(val))
        val = segv.register_value('%edx')
        self.assertEqual(val, 0xff600180, hex(val))
        val = segv.register_value('%dx')
        self.assertEqual(val, 0x0180, hex(val))
        val = segv.register_value('%dl')
        self.assertEqual(val, 0x80, hex(val))

    def test_segv_unknown(self):
        '''Handles unknown segfaults'''

        disasm = '''0x08083540 <main+0>:    mov    $1,%ecx'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
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
        self.assertEqual(segv.calculate_arg('0x10(,%ebx,1)'), 0x26f004, segv.regs['ebx'])

        # Again, but 64bit
        disasm = '''0x08083540 <main+0>:    mov    $1,%rcx'''
        segv = parse_segv.ParseSegv(regs64, disasm, maps)
        understood, reason, details = segv.report()
        self.assertFalse(understood, details)

        self.assertEqual(segv.calculate_arg('(%rax,%rbx,1)'), 0x26eff3, segv.regs['rbx'])

    def test_segv_pc_missing(self):
        '''Handles PC in missing VMA'''

        disasm = '''0x00083540 <main+0>:    lea    0x4(%esp),%ecx'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('PC (0x00083540) not located in a known VMA region' in details, details)
        self.assertTrue('executing unknown VMA' in reason, reason)

        disasm = '''0x00083544:'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('PC (0x00083544) not located in a known VMA region' in details, details)
        self.assertTrue('executing unknown VMA' in reason, reason)

    def test_segv_pc_null(self):
        '''Handles PC in NULL VMA'''

        disasm = '''0x00000540 <main+0>:    lea    0x4(%esp),%ecx'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('PC (0x00000540) not located in a known VMA region' in details, details)
        self.assertTrue('executing NULL VMA' in reason, reason)

    def test_segv_pc_nx_writable(self):
        '''Handles PC in writable NX VMA'''

        disasm = '''0x005a3000 <main+0>:    lea    0x4(%esp),%ecx'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('PC (0x005a3000) in non-executable VMA region:' in details, details)
        self.assertTrue('executing writable VMA /lib/libncurses.so.5.7' in reason, reason)

    def test_segv_pc_nx_unwritable(self):
        '''Handles PC in non-writable NX VMA'''

        disasm = '''0x00dfb000 <main+0>:    lea    0x4(%esp),%ecx'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('PC (0x00dfb000) in non-executable VMA region:' in details, details)
        self.assertTrue('executing non-writable VMA /lib/libreadline.so.5.2' in reason, reason)

    def test_segv_src_missing(self):
        '''Handles source in missing VMA'''

        reg = regs + 'ecx            0x0006af24   0xbfc6af24'
        disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

        # Valid crash
        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('source "-0x4(%ecx)" (0x0006af20) not located in a known VMA region' in details, details)
        self.assertTrue('reading unknown VMA' in reason, reason)

        # Valid crash
        disasm = '0x08083547 <main+7>:    callq  *%ecx'
        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('source "*%ecx" (0x0006af24) not located in a known VMA region' in details, details)
        self.assertTrue('reading unknown VMA' in reason, reason)

    def test_segv_src_null(self):
        '''Handles source in NULL VMA'''

        reg = regs + 'ecx            0x00000024   0xbfc6af24'
        disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('source "-0x4(%ecx)" (0x00000020) not located in a known VMA region' in details, details)
        self.assertTrue('reading NULL VMA' in reason, reason)

    def test_segv_src_not_readable(self):
        '''Handles source not in readable VMA'''

        reg = regs + 'ecx            0x0026c080   0xbfc6af24'
        disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'
        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('source "-0x4(%ecx)" (0x0026c07c) in non-readable VMA region:' in details, details)
        self.assertTrue('reading VMA /lib/tls/i686/cmov/libc-2.9.so' in reason, reason)
        self.assertFalse('Stack memory exhausted' in details, details)
        self.assertFalse('Stack pointer not within stack segment' in details, details)

    def test_segv_dest_missing(self):
        '''Handles destintation in missing VMA'''

        reg = regs + 'esp            0x0006af24   0xbfc6af24'
        disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('destination "(%esp)" (0x0006af24) not located in a known VMA region' in details, details)
        self.assertTrue('writing unknown VMA' in reason, reason)

    def test_segv_dest_null(self):
        '''Handles destintation in NULL VMA'''

        reg = regs + 'esp            0x00000024   0xbfc6af24'
        disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'

        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('destination "(%esp)" (0x00000024) not located in a known VMA region' in details, details)
        self.assertTrue('writing NULL VMA' in reason, reason)

    def test_segv_dest_not_writable(self):
        '''Handles destination not in writable VMA'''

        reg = regs + 'esp            0x08048080   0xbfc6af24'
        disasm = '0x08083547 <main+7>:    pushl  -0x4(%ecx)'
        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('destination "(%esp)" (0x08048080) in non-writable VMA region:' in details, details)
        self.assertTrue('writing VMA /usr/bin/gdb' in reason, reason)

    def test_segv_crackful_disasm(self):
        '''Rejects insane disassemblies'''

        disasm = '0x08083547 <main+7>:    pushl  -0x4(blah)'
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        self.assertRaises(ValueError, segv.report)

        disasm = '0x08083547 <main+7>:    pushl  -04(%ecx)'
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        self.assertRaises(ValueError, segv.report)

    def test_segv_stack_failure(self):
        '''Handles walking off the stack'''

        # Triggered via "push"
        reg = regs + 'esp            0xbfc56ff0   0xbfc56ff0'
        disasm = '0x08083547 <main+7>:    push  %eax'
        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('destination "(%esp)" (0xbfc56ff0) not located in a known VMA region (needed writable region)!' in details, details)

        # Triggered via "call"
        reg = regs + 'esp            0xbfc56fff   0xbfc56fff'
        disasm = '0x08083547 <main+7>:    callq  0x08083540'
        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('destination "(%esp)" (0xbfc56fff) not located in a known VMA region (needed writable region)!' in details, details)
        self.assertTrue('Stack memory exhausted' in details, details)

        # Triggered via unknown reason
        reg = regs + 'esp            0xdfc56000   0xdfc56000'
        disasm = '''0x08083540 <main+0>:    mov    $1,%rcx'''
        segv = parse_segv.ParseSegv(reg, disasm, maps)
        understood, reason, details = segv.report()
        self.assertTrue(understood, details)
        self.assertTrue('SP (0xdfc56000) not located in a known VMA region (needed readable region)!' in details, details)
        self.assertTrue('Stack pointer not within stack segment' in details, details)

    def test_segv_stack_kernel_segfault(self):
        '''Handles unknown segfaults in kernel'''

        # Crash in valid code path
        disasm = '''0x0056e010: ret'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        understood, reason, details = segv.report()
        self.assertFalse(understood, details)
        self.assertTrue('Reason could not be automatically determined.' in details, details)
        self.assertFalse('(Unhandled exception in kernel code?)' in details, details)

        # Crash from kernel code path
        disasm = '''0x00b67422 <__kernel_vsyscall+2>: ret'''
        segv = parse_segv.ParseSegv(regs, disasm, maps)
        understood, reason, details = segv.report()
        self.assertFalse(understood, details)
        self.assertTrue('Reason could not be automatically determined. (Unhandled exception in kernel code?)' in details, details)


unittest.main()
