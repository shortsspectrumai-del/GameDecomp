"""Explicit lowering of bounded Ghidra packed-byte pseudocode to GNU C.

The original source is never changed in place. AVAILABLE means a translation
was produced, not that it compiled or is equivalent. Only 64-bit little-endian
targets and packed values up to 16 bytes are modelled.
"""
import hashlib
import re

_RUNTIME = r'''
#include <stdint.h>
#include <stddef.h>
#if !defined(__SIZEOF_INT128__) || __SIZEOF_POINTER__ != 8 || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error GameDecomp compatibility requires a 64-bit little-endian GCC/Clang target with int128
#endif
typedef unsigned __int128 __gd_u128;
static inline __gd_u128 __gd_mask(unsigned n) {
  return n >= 16 ? ~(__gd_u128)0 : (((__gd_u128)1 << (n*8))-1);
}
static inline __gd_u128 __gd_load(const void *p,unsigned n) {
  if(n>16) __builtin_trap();
  __gd_u128 value=0; __builtin_memcpy(&value,p,n); return value;
}
static inline void __gd_store(void *p,unsigned n,__gd_u128 value) { if(n>16)__builtin_trap();__builtin_memcpy(p,&value,n); }
static inline __gd_u128 __gd_scalar(__gd_u128 value,unsigned unused) { (void)unused; return value; }
#define __gd_value(x) ({_Static_assert(sizeof(x)<=16,"unsupported packed value width"); \
 _Static_assert(!(__builtin_classify_type(x)==5 && __builtin_types_compatible_p(__typeof__(x),__typeof__((x)+0))),"packed pointer requires explicit dereference");_Generic((x), \
 unsigned char*:__gd_load, const unsigned char*:__gd_load, \
 char*:__gd_load, const char*:__gd_load, default:__gd_scalar)((x),sizeof(x));})
#define __gd_readpart(x,o,n) ({_Static_assert((o)+(n)<=sizeof(x),"slice outside observed storage");__gd_load((const unsigned char*)&(x)+(o),(n));})
#define __gd_writepart(x,o,n,v) do {_Static_assert((o)+(n)<=sizeof(x),"slice outside observed storage");__gd_store((unsigned char*)&(x)+(o),(n),__gd_value(v));} while(0)
static inline __gd_u128 __gd_shift(__gd_u128 v,unsigned s,unsigned n,int left) {
  v &= __gd_mask(n); return s>=n*8 ? 0 : ((left ? v<<s : v>>s)&__gd_mask(n));
}
static inline __gd_u128 __gd_concat(__gd_u128 h,__gd_u128 l,unsigned a,unsigned b) {
  return ((h&__gd_mask(a))<<(b*8)) | (l&__gd_mask(b));
}
static inline __gd_u128 __gd_sub(__gd_u128 v,unsigned offset,unsigned input,unsigned output) {
  return offset>=input ? 0 : (((v&__gd_mask(input))>>(offset*8))&__gd_mask(output));
}
static inline __gd_u128 __gd_sext(__gd_u128 v,unsigned a,unsigned b) {
  v &= __gd_mask(a); return v & ((__gd_u128)1<<(a*8-1)) ? v | (__gd_mask(b)^__gd_mask(a)) : v;
}
static inline __gd_u128 __gd_pshuflw(__gd_u128 value,unsigned control) {
  __gd_u128 out=value & ~__gd_mask(8);
  for(unsigned i=0;i<4;i++) out |= ((value >> (((control>>(i*2))&3)*16))&65535)<<(i*16);
  return out;
}
static inline __gd_u128 __gd_pshufhw(__gd_u128 value,unsigned control) {
  __gd_u128 out=value & __gd_mask(8);
  for(unsigned i=0;i<4;i++)out|=((value>>(64+((control>>(i*2))&3)*16))&65535)<<(64+i*16);
  return out;
}
static inline __gd_u128 __gd_psadbw(__gd_u128 a,__gd_u128 b) {
  __gd_u128 out=0;
  for(unsigned group=0;group<2;group++) {
    unsigned sum=0;
    for(unsigned i=group*8;i<group*8+8;i++) {
      int x=(unsigned char)(a>>(i*8)),y=(unsigned char)(b>>(i*8)); sum+=x>y?x-y:y-x;
    }
    out |= (__gd_u128)sum<<(group*64);
  }
  return out;
}
static inline uint32_t __gd_movmskps(__gd_u128 a) {
  uint32_t out=0;for(unsigned i=0;i<4;i++)out|=(uint32_t)((a>>(i*32+31))&1)<<i;return out;
}
static inline uint32_t __gd_pmovmskb(__gd_u128 a) {
  uint32_t out=0;for(unsigned i=0;i<16;i++)out|=(uint32_t)((a>>(i*8+7))&1)<<i;return out;
}
static inline __gd_u128 __gd_pshufd(__gd_u128 value,unsigned control) {
  __gd_u128 out=0;
  for(unsigned i=0;i<4;i++) out |= ((value >> (((control>>(i*2))&3)*32))&0xffffffffULL)<<(i*32);
  return out;
}
static inline __gd_u128 __gd_punpck(__gd_u128 a,__gd_u128 b,unsigned elem_bytes,int high) {
  __gd_u128 out=0, mask=__gd_mask(elem_bytes);
  unsigned count=8/elem_bytes, base=high?64:0, bits=elem_bytes*8;
  for(unsigned i=0;i<count;i++) {
    __gd_u128 va=(a>>(base+i*bits))&mask, vb=(b>>(base+i*bits))&mask;
    out |= (va<<(2*i*bits)) | (vb<<((2*i+1)*bits));
  }
  return out;
}
static inline __gd_u128 __gd_padd(__gd_u128 a,__gd_u128 b,unsigned elem_bytes,int sub) {
  __gd_u128 out=0, mask=__gd_mask(elem_bytes);
  unsigned count=16/elem_bytes, bits=elem_bytes*8;
  for(unsigned i=0;i<count;i++) {
    __gd_u128 va=(a>>(i*bits))&mask, vb=(b>>(i*bits))&mask;
    out |= ((sub ? (va-vb) : (va+vb))&mask)<<(i*bits);
  }
  return out;
}
static inline __gd_u128 __gd_pcmp(__gd_u128 a,__gd_u128 b,unsigned elem_bytes,int gt) {
  __gd_u128 out=0, mask=__gd_mask(elem_bytes);
  unsigned count=16/elem_bytes, bits=elem_bytes*8;
  for(unsigned i=0;i<count;i++) {
    __gd_u128 va=(a>>(i*bits))&mask, vb=(b>>(i*bits))&mask;
    int cond;
    if(!gt) cond=(va==vb);
    else if(elem_bytes==1) cond=((int8_t)va > (int8_t)vb);
    else if(elem_bytes==2) cond=((int16_t)va > (int16_t)vb);
    else cond=((int32_t)va > (int32_t)vb);
    if(cond) out |= mask<<(i*bits);
  }
  return out;
}
static inline __gd_u128 __gd_pminmax(__gd_u128 a,__gd_u128 b,unsigned elem_bytes,int is_max,int is_signed) {
  __gd_u128 out=0, mask=__gd_mask(elem_bytes);
  unsigned count=16/elem_bytes, bits=elem_bytes*8;
  for(unsigned i=0;i<count;i++) {
    __gd_u128 va=(a>>(i*bits))&mask, vb=(b>>(i*bits))&mask, chosen;
    if(is_signed) {
      int16_t sa=(int16_t)va, sb=(int16_t)vb;
      chosen = (uint16_t)(is_max ? (sa>sb?sa:sb) : (sa<sb?sa:sb));
    } else {
      uint8_t ua=(uint8_t)va, ub=(uint8_t)vb;
      chosen = is_max ? (ua>ub?ua:ub) : (ua<ub?ua:ub);
    }
    out |= (chosen&mask)<<(i*bits);
  }
  return out;
}
static inline int __gd_carry(__gd_u128 a,__gd_u128 b,unsigned n) {
  __gd_u128 m=__gd_mask(n), ua=a&m, ub=b&m; return ((ua+ub)&m) < ua;
}
static inline int __gd_scarry(__gd_u128 a,__gd_u128 b,unsigned n) {
  __gd_u128 m=__gd_mask(n), ua=a&m, ub=b&m, s=(ua+ub)&m;
  return (int)((((~(ua^ub))&(ua^s))>>(n*8-1))&1);
}
static inline int __gd_sborrow(__gd_u128 a,__gd_u128 b,unsigned n) {
  __gd_u128 m=__gd_mask(n), ua=a&m, ub=b&m, d=(ua-ub)&m;
  return (int)((((ua^ub)&(ua^d))>>(n*8-1))&1);
}
static inline uint8_t __gd_popcount(__gd_u128 v) {
  return (uint8_t)(__builtin_popcountll((uint64_t)v)+__builtin_popcountll((uint64_t)(v>>64)));
}
/* Ghidra models the old destination as an artificial unused input. */
#define pshuflw(old,source,control) __gd_pshuflw((source),(control))
#define pshufhw(old,source,control) __gd_pshufhw((source),(control))
#define __gd_pshufd_2(source,control) __gd_pshufd((source),(control))
#define __gd_pshufd_3(old,source,control) __gd_pshufd((source),(control))
#define __gd_select_3(_1,_2,_3,NAME,...) NAME
#define pshufd(...) __gd_select_3(__VA_ARGS__,__gd_pshufd_3,__gd_pshufd_2)(__VA_ARGS__)
#define psadbw(a,b) __gd_psadbw((a),(b))
#define movmskps(old,source) __gd_movmskps((source))
#define __gd_pmovmskb_1(source) __gd_pmovmskb((source))
#define __gd_pmovmskb_2(old,source) __gd_pmovmskb((source))
#define __gd_select_2(_1,_2,NAME,...) NAME
#define pmovmskb(...) __gd_select_2(__VA_ARGS__,__gd_pmovmskb_2,__gd_pmovmskb_1)(__VA_ARGS__)
#define punpcklbw(a,b) __gd_punpck((a),(b),1,0)
#define punpckhbw(a,b) __gd_punpck((a),(b),1,1)
#define punpcklwd(a,b) __gd_punpck((a),(b),2,0)
#define punpckhwd(a,b) __gd_punpck((a),(b),2,1)
#define punpckldq(a,b) __gd_punpck((a),(b),4,0)
#define punpckhdq(a,b) __gd_punpck((a),(b),4,1)
#define punpcklqdq(a,b) __gd_punpck((a),(b),8,0)
#define punpckhqdq(a,b) __gd_punpck((a),(b),8,1)
#define paddb(a,b) __gd_padd((a),(b),1,0)
#define paddw(a,b) __gd_padd((a),(b),2,0)
#define paddd(a,b) __gd_padd((a),(b),4,0)
#define paddq(a,b) __gd_padd((a),(b),8,0)
#define psubb(a,b) __gd_padd((a),(b),1,1)
#define psubw(a,b) __gd_padd((a),(b),2,1)
#define psubd(a,b) __gd_padd((a),(b),4,1)
#define psubq(a,b) __gd_padd((a),(b),8,1)
#define pcmpeqb(a,b) __gd_pcmp((a),(b),1,0)
#define pcmpeqw(a,b) __gd_pcmp((a),(b),2,0)
#define pcmpeqd(a,b) __gd_pcmp((a),(b),4,0)
#define pcmpgtb(a,b) __gd_pcmp((a),(b),1,1)
#define pcmpgtw(a,b) __gd_pcmp((a),(b),2,1)
#define pcmpgtd(a,b) __gd_pcmp((a),(b),4,1)
#define pminub(a,b) __gd_pminmax((a),(b),1,0,0)
#define pmaxub(a,b) __gd_pminmax((a),(b),1,1,0)
#define pminsw(a,b) __gd_pminmax((a),(b),2,0,1)
#define pmaxsw(a,b) __gd_pminmax((a),(b),2,1,1)
#define pand(a,b) (((__gd_u128)(a))&((__gd_u128)(b)))
#define pandn(a,b) ((~((__gd_u128)(a)))&((__gd_u128)(b)))
#define por(a,b) (((__gd_u128)(a))|((__gd_u128)(b)))
#define pxor(a,b) (((__gd_u128)(a))^((__gd_u128)(b)))
#define CARRY1(a,b) __gd_carry((a),(b),1)
#define CARRY2(a,b) __gd_carry((a),(b),2)
#define CARRY4(a,b) __gd_carry((a),(b),4)
#define CARRY8(a,b) __gd_carry((a),(b),8)
#define SCARRY1(a,b) __gd_scarry((a),(b),1)
#define SCARRY2(a,b) __gd_scarry((a),(b),2)
#define SCARRY4(a,b) __gd_scarry((a),(b),4)
#define SCARRY8(a,b) __gd_scarry((a),(b),8)
#define SBORROW1(a,b) __gd_sborrow((a),(b),1)
#define SBORROW2(a,b) __gd_sborrow((a),(b),2)
#define SBORROW4(a,b) __gd_sborrow((a),(b),4)
#define SBORROW8(a,b) __gd_sborrow((a),(b),8)
#define POPCOUNT(x) __gd_popcount((__gd_u128)(x))
'''


def _widths(family, digits):
    choices = []
    for split in range(1, len(digits)):
        a, b = int(digits[:split]), int(digits[split:])
        if not 1 <= a <= 16 or not 1 <= b <= 16:
            continue
        valid = (a+b <= 16 if family == 'CONCAT' else b <= a if family == 'SUB' else a <= b)
        if valid:
            choices.append((a, b))
    return choices[0] if len(choices) == 1 else None


def _ctype(size):
    return 'uint8_t' if size <= 1 else 'uint16_t' if size <= 2 else 'uint32_t' if size <= 4 else 'uint64_t' if size <= 8 else '__gd_u128'


def lower_ghidra_source(source, *, bits=64, endianness='little'):
    result = {'status': 'UNKNOWN', 'source': None, 'preamble': '', 'diagnostics': [],
              'transformations': [], 'semantic_status': 'UNKNOWN'}
    try:
        size = len(source.encode()) if isinstance(source, str) else 1_000_001
    except UnicodeEncodeError:
        size = 1_000_001
    if (not isinstance(source, str) or '\0' in source or size > 1_000_000
            or bits != 64 or endianness != 'little'):
        result['diagnostics'].append('Unsupported source budget or target; no lowering guessed')
        return result
    if '__gd_' in source or '__GD_PROTECTED_' in source:
        result['diagnostics'].append('Reserved compatibility identifier collision')
        return result
    protected = []
    def hold(text):
        protected.append(text)
        return f'__GD_PROTECTED_{len(protected)-1}__'
    # Comments and literals must never be interpreted as pseudocode.
    code = re.sub(r'/\*.*?\*/|//[^\r\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: hold(m[0]), source, flags=re.S)
    if re.search(r'\b(?:in_register_|unaff_|extraout_)[A-Za-z_0-9]+\b', code):
        result['diagnostics'].append('Unrecovered register state: lowering would preserve an undefined C read; ABI recovery required')
        return result
    for match in re.finditer(r'\b(pshuflw|pshufhw|pshufd|movmskps|pmovmskb)\s*\(', code):
        intrinsic = match.group(1)
        depth, pos, start = 0, match.end(), match.end()
        args = []
        while pos < len(code):
            character = code[pos]
            if character == ',' and depth == 0:
                args.append(code[start:pos])
                start = pos + 1
            elif character == '(':
                depth += 1
            elif character == ')':
                if depth == 0:
                    args.append(code[start:pos])
                    break
                depth -= 1
            pos += 1
        if pos >= len(code) or code[pos] != ')':
            result['diagnostics'].append('Artificial destination with unsupported expression')
            return result
        has_artificial = ((intrinsic in ('pshuflw', 'pshufhw') and len(args) == 3)
                          or (intrinsic == 'movmskps' and len(args) == 2)
                          or (intrinsic == 'pshufd' and len(args) == 3)
                          or (intrinsic == 'pmovmskb' and len(args) == 2))
        valid_arity = (has_artificial
                       or (intrinsic == 'pshufd' and len(args) == 2)
                       or (intrinsic == 'pmovmskb' and len(args) == 1))
        if not valid_arity:
            result['diagnostics'].append('Artificial destination with unsupported expression')
            return result
        if has_artificial:
            operand = args[0]
            calls = re.findall(r'\b([A-Za-z_]\w*)\s*\(', operand)
            if ('++' in operand or '--' in operand
                    or re.search(r'(?<![=!<>])=(?!=)', operand)
                    or any(not re.fullmatch(r'(?:CONCAT|SUB|ZEXT|SEXT)\d+|(?:CARRY|SCARRY|SBORROW)[1248]|POPCOUNT', name) for name in calls)):
                result['diagnostics'].append('Artificial destination with unsupported expression')
                return result
    if any(not 1 <= int(n) <= 16 for n in re.findall(r'\._\d+_(\d+)_', code)):
        result['diagnostics'].append('Unsupported slice width')
        return result
    macros = []
    for family, digits in sorted(set(re.findall(r'\b(CONCAT|SUB|ZEXT|SEXT)(\d+)\s*\(', code))):
        widths = _widths(family, digits)
        if widths is None:
            result['diagnostics'].append(f'Unsupported or ambiguous packed widths: {family}{digits}')
            return result
        a, b = widths
        name = family+digits
        if family == 'CONCAT':
            expr, args, size = f'__gd_concat((h),(l),{a},{b})', 'h,l', a+b
        elif family == 'SUB':
            expr, args, size = f'__gd_sub((v),(o),{a},{b})', 'v,o', b
        elif family == 'ZEXT':
            expr, args, size = f'((__gd_u128)(v)&__gd_mask({a}))', 'v', b
        else:
            expr, args, size = f'__gd_sext((v),{a},{b})', 'v', b
        macros.append(f'#define {name}({args}) (({_ctype(size)})({expr}))\n')
    array_ptrs = {}
    for ptr_match in re.finditer(r'\b(?:undefined1|uint8_t|unsigned\s+char|byte|char)\s*\(\s*\*\s*(\w+)\s*\)\s*\[\s*(\d+)\s*\]', code):
        ptr_name, ptr_size = ptr_match.group(1), int(ptr_match.group(2))
        if 1 <= ptr_size <= 16:
            array_ptrs[ptr_name] = ptr_size
    vectors = {}
    def declaration(m):
        name, size = m[2], int(m[3])
        if not 1 <= size <= 16:
            return m[0]
        vectors[name] = size
        return hold(m[0])
    code = re.sub(r'\b(undefined1|uint8_t|unsigned\s+char|byte|char)\s+(auVar\w*)\s*\[\s*(\d+)\s*]\s*;', declaration, code)
    # Array rvalue casts are packed bit patterns, not valid ISO C array casts.
    code = re.sub(r'\(\s*(?:undefined1|uint8_t|unsigned\s+char|byte)\s*\[\s*(\d+)\s*]\s*\)',
                  lambda m: '(__gd_u128)' if 1 <= int(m[1]) <= 16 else m[0], code)
    for size in sorted(set(int(n) for n in re.findall(r'\bunkuint(\d+)\b', code))):
        if not 1 <= size <= 16:
            result['diagnostics'].append('Unsupported wide packed scalar')
            return result
        macros.append(f'typedef __gd_u128 unkuint{size};\n')
    # Assigning to an array copies exactly the observed number of bytes.
    memory_lhs = r'(\*\s*\(\s*(?:undefined1|uint8_t|unsigned\s+char|byte)\s*\(\s*\*\s*\)\s*\[\s*(\d+)\s*]\s*\)\s*[^;=]+)'
    def store_array(m):
        lhs, n, rhs = m[1], int(m[2]), m[3]
        if not 1 <= n <= 16:
            return m[0]
        return f'__gd_store((void*)&({hold(lhs)}),{n},__gd_value({rhs}));'
    code = re.sub(memory_lhs+r'\s*=\s*([^;]+);', store_array, code)
    for ptr_name, ptr_size in array_ptrs.items():
        code = re.sub(r'\*\s*' + re.escape(ptr_name) + r'\s*(?<![=!<>])=(?!=)\s*([^;]+);',
                      lambda m, n=ptr_name, s=ptr_size: f'__gd_store((void*)&(*{hold(n)}),{s},__gd_value({m[1]}));', code)
        code = re.sub(r'\b' + re.escape(ptr_name) + r'\s*\[\s*([^\[\];]+)\s*\]\s*(?<![=!<>])=(?!=)\s*([^;]+);',
                      lambda m, n=ptr_name, s=ptr_size: f'__gd_store((void*)&({hold(n)}[{m[1]}]),{s},__gd_value({m[2]}));', code)
    # Slice destinations are changed before slice reads; no read-modify-write
    # of uninitialised neighbouring bytes is introduced.
    code = re.sub(r'\b(\w+)\._(\d+)_(\d+)_\s*=\s*([^;]+);',
                  lambda m: f'__gd_writepart({hold(m[1])},{m[2]},{m[3]},{m[4]});', code)
    code = re.sub(r'\b(\w+)\._(\d+)_(\d+)_',
                  lambda m: f'__gd_readpart({hold(m[1])},{m[2]},{m[3]})', code)
    for name, size in vectors.items():
        # Whole-array assignments use a byte copy. Array RHS loads retain
        # sizeof(array), unlike pointer decay.
        code = re.sub(r'\b'+re.escape(name)+r'\s*=\s*([^;]+);',
                      lambda m: f'__gd_store({hold(name)},{size},__gd_value({m[1]}));', code)
        code = re.sub(r'\b'+re.escape(name)+r'\s*(<<|>>)\s*(0[xX][0-9a-fA-F]+|\d+)\b',
                      lambda m: f'__gd_shift(__gd_load({hold(name)},{size}),{m[2]},{size},{int(m[1]=="<<")})', code)
        # Indexing is byte addressing. Protect the identifier, keep index and
        # lvalue operations intact, then lower remaining packed value uses.
        code = re.sub(r'\b'+re.escape(name)+r'(?=\s*\[)', lambda m: hold(name), code)
        code = re.sub(r'\b'+re.escape(name)+r'\b', lambda m: f'__gd_load({hold(name)},{size})', code)
    if re.search(r'\._\d+_\d+_|(?:undefined1|uint8_t)\s*\[\s*(?:1[0-6]|[1-9])\s*]\s*\)', code):
        result['diagnostics'].append('Packed expression outside the supported grammar')
        return result
    # Restore nested placeholders from newest to oldest.
    for index in range(len(protected)-1, -1, -1):
        code = code.replace(f'__GD_PROTECTED_{index}__', protected[index])
    result.update(status='AVAILABLE', source=code, preamble=_RUNTIME+''.join(macros),
                  transformations=['packed-byte copies/slices', 'bounded integer pseudo-operations',
                                   'SSE2 PSHUFLW/PSHUFHW/PSHUFD/PSADBW/PUNPCK/PCMP/PADD/PSUB/PMINMAX and MOVMSKPS/PMOVMSKB models'],
                  source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                  lowered_sha256=hashlib.sha256(code.encode()).hexdigest(),
                  preamble_sha256=hashlib.sha256((_RUNTIME+''.join(macros)).encode()).hexdigest())
    return result

