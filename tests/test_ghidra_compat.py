import random
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from gamedecomp.ghidra_compat import lower_ghidra_source


class GhidraCompatTests(unittest.TestCase):
    def test_unknown_width_and_target_are_not_guessed(self):
        for text, kwargs in [('int f(){return CONCAT111(1,2);}', {}),
                             ('int f(){return 1;}', {'endianness': 'big'}),
                             ('int f(){return SUB321(1,0);}', {})]:
            result = lower_ghidra_source(text, **kwargs)
            self.assertEqual(result['status'], 'UNKNOWN')
            self.assertIsNone(result['source'])

    def test_invalid_unicode_collisions_and_side_effects_are_rejected(self):
        for source in ('\ud800', 'int __GD_PROTECTED_0__;',
                       'int f(){return movmskps(++value,packed);}',
                       'int f(){return movmskps(side_effect(),packed);}'):
            self.assertEqual(lower_ghidra_source(source)['status'], 'UNKNOWN')

    def test_artificial_destination_accepts_nested_pure_pcode(self):
        source = 'int f(){return movmskps((int)CONCAT71((unsigned long)(value >> 8),byte),packed);}'
        self.assertEqual(lower_ghidra_source(source)['status'], 'AVAILABLE')

    def test_unrecovered_register_cannot_be_compiled_into_an_undefined_read(self):
        # Regression discovered in the real Clang -O2 DWARF findTarget body.
        source = 'unsigned char target(unsigned char x) { unsigned long in_register_00000031; return (int)CONCAT71(in_register_00000031,x)==0 ? 0 : 252; }'
        result = lower_ghidra_source(source)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIn('Unrecovered register state', result['diagnostics'][0])

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_packed_pointer_is_not_silently_treated_as_array_value(self):
        lowered = lower_ghidra_source('void f(unsigned char *p){ unsigned char auVar1[16]; auVar1=p; }')
        from gamedecomp.validation import compile_source
        result = compile_source(lowered['preamble']+lowered['source'])
        self.assertEqual(result['status'], 'COMPILE_FAILED')
        self.assertIn('packed pointer requires explicit dereference', '\n'.join(result['diagnostics']))

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_packed_memory_slices_preserve_neighbours_and_single_evaluation(self):
        source = '''unsigned long recovered(unsigned char *p) {
          unsigned char auVar1[16]; unsigned char auVar2[15];
          auVar1 = *(unsigned char (*)[16])p;
          auVar2._0_8_ = auVar1._1_8_;
          auVar2._8_7_ = auVar1._9_7_;
          auVar1._3_8_ = auVar2._0_8_;
          *(unsigned char (*)[16])p = auVar1;
          return SUB168(auVar1 >> 0x40,0);
        }
        unsigned long concat_once(int *h,int *l) { return CONCAT44(++*h,++*l); }
        '''
        result = lower_ghidra_source(source)
        self.assertEqual(result['status'], 'AVAILABLE', result['diagnostics'])
        harness = '''int main(void) {
          unsigned char p[18]; for(int i=0;i<18;i++)p[i]=i;
          recovered(p+1);
          for(int i=0;i<18;i++) {
            int expected = i>=4 && i<12 ? i-2 : i;
            if(p[i]!=expected) return i+1;
          }
          int high=0,low=10;
          unsigned long v=concat_once(&high,&low);
          if(high!=1 || low!=11 || v!=0x10000000bUL) return 30;
          return 0;
        }'''
        self.run_c(result['preamble'] + result['source'] + harness)

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_simd_helpers_against_hardware_sse2_all_shuffle_immediates(self):
        # Independent CPU intrinsics oracle, including all 256 shuffle controls.
        source = '''void recovered(unsigned char *a,unsigned char *b,int control,unsigned char *out) {
          unsigned char auVar1[16]; unsigned char auVar2[16]; unsigned char auVar3[16];
          auVar1=*(unsigned char (*)[16])a; auVar2=*(unsigned char (*)[16])b;
          auVar3=pshuflw(auVar2,auVar1,control);
          *(unsigned char (*)[16])out=auVar3;
          auVar3=psadbw(auVar1,auVar2);
          *(unsigned char (*)[16])(out+16)=auVar3;
          *(unsigned int *)(out+32)=movmskps(123,auVar1);
          auVar3=pshufhw(auVar2,auVar1,control);
          *(unsigned char (*)[16])(out+36)=auVar3;
        }'''
        result = lower_ghidra_source(source)
        self.assertEqual(result['status'], 'AVAILABLE', result['diagnostics'])
        shuffle_cases = '\n'.join(f'case {i}: expected=_mm_shufflelo_epi16(x,{i}); upper=_mm_shufflehi_epi16(x,{i}); break;' for i in range(256))
        harness = '''
        #include <string.h>
        #include <emmintrin.h>
        #include <xmmintrin.h>
        int main(void) {
          unsigned int seed=2048;
          for(int trial=0;trial<8192;trial++) {
            unsigned char a[16],b[16],actual[52],reference[52];
            for(int i=0;i<16;i++){seed=seed*1664525u+1013904223u;a[i]=seed>>24;seed=seed*1664525u+1013904223u;b[i]=seed>>24;}
            __m128i x=_mm_loadu_si128((const __m128i*)a),y=_mm_loadu_si128((const __m128i*)b),expected,upper;
            int control=trial&255;
            switch(control){SHUFFLES}
            _mm_storeu_si128((__m128i*)reference,expected);
            _mm_storeu_si128((__m128i*)(reference+16),_mm_sad_epu8(x,y));
            unsigned int mask=_mm_movemask_ps(_mm_castsi128_ps(x));memcpy(reference+32,&mask,4);
            _mm_storeu_si128((__m128i*)(reference+36),upper);
            recovered(a,b,control,actual);
            if(memcmp(actual,reference,52)) return 1;
          }
          return 0;
        }'''.replace('SHUFFLES', shuffle_cases)
        self.run_c(result['preamble'] + result['source'] + harness)

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_packed_array_pointer_stores_compile_and_execute(self):
        # Exact pattern emitted by Ghidra for 2048 initBoard (GCC/Clang -O2).
        source = '''typedef unsigned char undefined1;
        void initBoard(undefined1 (*param_1) [16]) {
          *param_1 = (undefined1 [16])0x0;
          param_1[1] = (undefined1 [16])0x0;
          return;
        }'''
        result = lower_ghidra_source(source)
        self.assertEqual(result['status'], 'AVAILABLE', result['diagnostics'])
        harness = '''int main(void) {
          unsigned char board[32];
          for(int i=0;i<32;i++) board[i] = (unsigned char)(0xa5 + i);
          initBoard((unsigned char (*)[16])board);
          for(int i=0;i<32;i++) if(board[i] != 0) return i + 1;
          return 0;
        }'''
        self.run_c(result['preamble'] + result['source'] + harness)

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_expanded_sse2_intrinsics_against_hardware_oracle(self):
        source = '''void simd_all(unsigned char *a,unsigned char *b,int control,unsigned char *out,unsigned int *masks) {
          unsigned char auVar1[16]; unsigned char auVar2[16]; unsigned char auVar3[16];
          auVar1=*(unsigned char (*)[16])a; auVar2=*(unsigned char (*)[16])b;
          auVar3=pshufd(auVar2,auVar1,control); *(unsigned char (*)[16])(out+0)=auVar3;
          auVar3=pshufd(auVar1,control);        *(unsigned char (*)[16])(out+16)=auVar3;
          auVar3=punpcklbw(auVar1,auVar2);      *(unsigned char (*)[16])(out+32)=auVar3;
          auVar3=punpckhbw(auVar1,auVar2);      *(unsigned char (*)[16])(out+48)=auVar3;
          auVar3=punpcklwd(auVar1,auVar2);      *(unsigned char (*)[16])(out+64)=auVar3;
          auVar3=punpckhwd(auVar1,auVar2);      *(unsigned char (*)[16])(out+80)=auVar3;
          auVar3=punpckldq(auVar1,auVar2);      *(unsigned char (*)[16])(out+96)=auVar3;
          auVar3=punpckhdq(auVar1,auVar2);      *(unsigned char (*)[16])(out+112)=auVar3;
          auVar3=punpcklqdq(auVar1,auVar2);     *(unsigned char (*)[16])(out+128)=auVar3;
          auVar3=punpckhqdq(auVar1,auVar2);     *(unsigned char (*)[16])(out+144)=auVar3;
          auVar3=paddb(auVar1,auVar2);          *(unsigned char (*)[16])(out+160)=auVar3;
          auVar3=paddw(auVar1,auVar2);          *(unsigned char (*)[16])(out+176)=auVar3;
          auVar3=paddd(auVar1,auVar2);          *(unsigned char (*)[16])(out+192)=auVar3;
          auVar3=paddq(auVar1,auVar2);          *(unsigned char (*)[16])(out+208)=auVar3;
          auVar3=psubb(auVar1,auVar2);          *(unsigned char (*)[16])(out+224)=auVar3;
          auVar3=psubw(auVar1,auVar2);          *(unsigned char (*)[16])(out+240)=auVar3;
          auVar3=psubd(auVar1,auVar2);          *(unsigned char (*)[16])(out+256)=auVar3;
          auVar3=psubq(auVar1,auVar2);          *(unsigned char (*)[16])(out+272)=auVar3;
          auVar3=pcmpeqb(auVar1,auVar2);        *(unsigned char (*)[16])(out+288)=auVar3;
          auVar3=pcmpeqw(auVar1,auVar2);        *(unsigned char (*)[16])(out+304)=auVar3;
          auVar3=pcmpeqd(auVar1,auVar2);        *(unsigned char (*)[16])(out+320)=auVar3;
          auVar3=pcmpgtb(auVar1,auVar2);        *(unsigned char (*)[16])(out+336)=auVar3;
          auVar3=pcmpgtw(auVar1,auVar2);        *(unsigned char (*)[16])(out+352)=auVar3;
          auVar3=pcmpgtd(auVar1,auVar2);        *(unsigned char (*)[16])(out+368)=auVar3;
          auVar3=pminub(auVar1,auVar2);         *(unsigned char (*)[16])(out+384)=auVar3;
          auVar3=pmaxub(auVar1,auVar2);         *(unsigned char (*)[16])(out+400)=auVar3;
          auVar3=pminsw(auVar1,auVar2);         *(unsigned char (*)[16])(out+416)=auVar3;
          auVar3=pmaxsw(auVar1,auVar2);         *(unsigned char (*)[16])(out+432)=auVar3;
          auVar3=pand(auVar1,auVar2);           *(unsigned char (*)[16])(out+448)=auVar3;
          auVar3=pandn(auVar1,auVar2);          *(unsigned char (*)[16])(out+464)=auVar3;
          auVar3=por(auVar1,auVar2);            *(unsigned char (*)[16])(out+480)=auVar3;
          auVar3=pxor(auVar1,auVar2);           *(unsigned char (*)[16])(out+496)=auVar3;
          masks[0]=pmovmskb(123,auVar1);
          masks[1]=pmovmskb(auVar2);
        }'''
        result = lower_ghidra_source(source)
        self.assertEqual(result['status'], 'AVAILABLE', result['diagnostics'])
        shuffle_cases = '\n'.join(f'case {i}: shuf=_mm_shuffle_epi32(x,{i}); break;' for i in range(256))
        harness = '''
        #include <string.h>
        #include <emmintrin.h>
        int main(void) {
          unsigned int seed=0x13579bdfU;
          for(int trial=0;trial<1024;trial++) {
            unsigned char a[16],b[16],actual[512],ref[512];
            unsigned int masks[2],ref_masks[2];
            for(int i=0;i<16;i++){
              seed=seed*1664525u+1013904223u; a[i]=(trial%5==0 && i%3==0)?0x80:(unsigned char)(seed>>24);
              seed=seed*1664525u+1013904223u; b[i]=(trial%5==0 && i%3==0)?0x80:(unsigned char)(seed>>24);
            }
            __m128i x=_mm_loadu_si128((const __m128i*)a),y=_mm_loadu_si128((const __m128i*)b),shuf;
            int control=trial&255;
            switch(control){SHUFFLES}
            _mm_storeu_si128((__m128i*)(ref+0),shuf);
            _mm_storeu_si128((__m128i*)(ref+16),shuf);
            _mm_storeu_si128((__m128i*)(ref+32),_mm_unpacklo_epi8(x,y));
            _mm_storeu_si128((__m128i*)(ref+48),_mm_unpackhi_epi8(x,y));
            _mm_storeu_si128((__m128i*)(ref+64),_mm_unpacklo_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+80),_mm_unpackhi_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+96),_mm_unpacklo_epi32(x,y));
            _mm_storeu_si128((__m128i*)(ref+112),_mm_unpackhi_epi32(x,y));
            _mm_storeu_si128((__m128i*)(ref+128),_mm_unpacklo_epi64(x,y));
            _mm_storeu_si128((__m128i*)(ref+144),_mm_unpackhi_epi64(x,y));
            _mm_storeu_si128((__m128i*)(ref+160),_mm_add_epi8(x,y));
            _mm_storeu_si128((__m128i*)(ref+176),_mm_add_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+192),_mm_add_epi32(x,y));
            _mm_storeu_si128((__m128i*)(ref+208),_mm_add_epi64(x,y));
            _mm_storeu_si128((__m128i*)(ref+224),_mm_sub_epi8(x,y));
            _mm_storeu_si128((__m128i*)(ref+240),_mm_sub_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+256),_mm_sub_epi32(x,y));
            _mm_storeu_si128((__m128i*)(ref+272),_mm_sub_epi64(x,y));
            _mm_storeu_si128((__m128i*)(ref+288),_mm_cmpeq_epi8(x,y));
            _mm_storeu_si128((__m128i*)(ref+304),_mm_cmpeq_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+320),_mm_cmpeq_epi32(x,y));
            _mm_storeu_si128((__m128i*)(ref+336),_mm_cmpgt_epi8(x,y));
            _mm_storeu_si128((__m128i*)(ref+352),_mm_cmpgt_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+368),_mm_cmpgt_epi32(x,y));
            _mm_storeu_si128((__m128i*)(ref+384),_mm_min_epu8(x,y));
            _mm_storeu_si128((__m128i*)(ref+400),_mm_max_epu8(x,y));
            _mm_storeu_si128((__m128i*)(ref+416),_mm_min_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+432),_mm_max_epi16(x,y));
            _mm_storeu_si128((__m128i*)(ref+448),_mm_and_si128(x,y));
            _mm_storeu_si128((__m128i*)(ref+464),_mm_andnot_si128(x,y));
            _mm_storeu_si128((__m128i*)(ref+480),_mm_or_si128(x,y));
            _mm_storeu_si128((__m128i*)(ref+496),_mm_xor_si128(x,y));
            ref_masks[0]=(unsigned int)_mm_movemask_epi8(x);
            ref_masks[1]=(unsigned int)_mm_movemask_epi8(y);
            simd_all(a,b,control,actual,masks);
            if(memcmp(actual,ref,512) || masks[0]!=ref_masks[0] || masks[1]!=ref_masks[1]) return 1;
          }
          return 0;
        }'''.replace('SHUFFLES', shuffle_cases)
        self.run_c(result['preamble'] + result['source'] + harness)

    @unittest.skipUnless(shutil.which('gcc'), 'gcc required')
    def test_pcode_carry_scarry_sborrow_and_popcount(self):
        source = '''unsigned int flags_test(unsigned long a, unsigned long b) {
          unsigned int r = 0;
          r |= (CARRY1(a, b) ? 1u : 0u) << 0;
          r |= (CARRY2(a, b) ? 1u : 0u) << 1;
          r |= (CARRY4(a, b) ? 1u : 0u) << 2;
          r |= (CARRY8(a, b) ? 1u : 0u) << 3;
          r |= (SCARRY1(a, b) ? 1u : 0u) << 4;
          r |= (SCARRY2(a, b) ? 1u : 0u) << 5;
          r |= (SCARRY4(a, b) ? 1u : 0u) << 6;
          r |= (SCARRY8(a, b) ? 1u : 0u) << 7;
          r |= (SBORROW1(a, b) ? 1u : 0u) << 8;
          r |= (SBORROW2(a, b) ? 1u : 0u) << 9;
          r |= (SBORROW4(a, b) ? 1u : 0u) << 10;
          r |= (SBORROW8(a, b) ? 1u : 0u) << 11;
          r |= ((unsigned int)POPCOUNT(a ^ b)) << 16;
          return r;
        }'''
        result = lower_ghidra_source(source)
        self.assertEqual(result['status'], 'AVAILABLE', result['diagnostics'])
        harness = '''int main(void) {
          if(!(flags_test(0xff, 1) & (1u << 0))) return 1;
          if(!(flags_test(0xffff, 1) & (1u << 1))) return 2;
          if(!(flags_test(0xffffffffUL, 1) & (1u << 2))) return 3;
          if(!(flags_test(0xffffffffffffffffUL, 1) & (1u << 3))) return 4;
          if(!(flags_test(0x7f, 1) & (1u << 4))) return 5;
          if(!(flags_test(0x7fff, 1) & (1u << 5))) return 6;
          if(!(flags_test(0x7fffffffUL, 1) & (1u << 6))) return 7;
          if(!(flags_test(0x7fffffffffffffffUL, 1) & (1u << 7))) return 8;
          if(!(flags_test(0x80, 1) & (1u << 8))) return 9;
          if(!(flags_test(0x8000, 1) & (1u << 9))) return 10;
          if(!(flags_test(0x80000000UL, 1) & (1u << 10))) return 11;
          if(!(flags_test(0x8000000000000000UL, 1) & (1u << 11))) return 12;
          if((flags_test(0xf0f0f0f0UL, 0x0f0f0f0fUL) >> 16) != 32u) return 13;
          return 0;
        }'''
        self.run_c(result['preamble'] + result['source'] + harness)

    def run_c(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'fixture.c'; path.write_text(source)
            compiled = subprocess.run(['gcc','-std=gnu11','-O2','-msse2','-Wall',str(path),'-o',str(root/'fixture')], capture_output=True,timeout=30)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
            run = subprocess.run([str(root/'fixture')],capture_output=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr.decode())

