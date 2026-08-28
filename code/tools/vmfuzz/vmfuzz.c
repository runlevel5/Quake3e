/*
===========================================================================
vmfuzz — QVM differential fuzzer

Builds short ENTER/body/LEAVE QVM programs that return a single int32,
executes each under the bytecode interpreter and the JIT, and reports
any divergence in the return value.

Program bodies are random sequences of "islands" drawn from the QVM op
families (arithmetic, bitwise, shifts, sign extension, unary, DIV/MOD,
safe and dynamic-address LOAD/STORE at byte/halfword/word widths,
OP_BLOCK_COPY, OP_JUMP, conditional integer and float compares,
OP_CALL with a self-recursive helper function, float arithmetic and
unary, and TRAP_SQRT).  Operand value choices are biased toward
boundary cases likely to expose immediate-encoding and sign-extension
bugs in the JIT.

On divergence: prints the generated op stream and saves the .qvm bytes
to /tmp/vmfuzz-fail-<seed>.qvm so the failing input can be replayed.

Build is wired through CMakeLists.txt as the optional `vmfuzz` target;
it pulls in vm.c, vm_interpreted.c, the active backend's vm_*.c,
q_shared.c, q_math.c, and supplies just the engine-API stubs they need.

Environment knobs:
  VMFUZZ_RTCHECKS=<int>  override vm_rtChecks (default 15 = all checks)
  VMFUZZ_NOBRANCH=1       suppress conditional-branch islands
  VMFUZZ_DEBUG=1          dump vm_t setup, JIT prologue, and return value
===========================================================================
*/

#include "../../qcommon/q_shared.h"
#include "../../qcommon/qcommon.h"
#include "../../qcommon/vm_local.h"
#include "../../qcommon/qfiles.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>


// =========================================================================
// Engine API stubs — minimum surface to link vm.c + vm_powerpc.c + vm_interpreted.c
// =========================================================================

void Com_Printf( const char *fmt, ... )
{
	va_list ap;
	va_start( ap, fmt );
	vfprintf( stderr, fmt, ap );
	va_end( ap );
}

void Com_DPrintf( const char *fmt, ... )
{
	(void)fmt;
}

void QDECL Com_Error( errorParm_t code, const char *fmt, ... )
{
	va_list ap;
	(void)code;
	fprintf( stderr, "Com_Error: " );
	va_start( ap, fmt );
	vfprintf( stderr, fmt, ap );
	va_end( ap );
	fprintf( stderr, "\n" );
	exit( 2 );
}
// Note: Com_Memset / Com_Memcpy are macros over memset/memcpy in q_shared.h

void *Z_Malloc( size_t size ) { return calloc( 1, size ); }
void  Z_Free( void *p ) { free( p ); }

void *Hunk_Alloc( size_t size, ha_pref pref ) { (void)pref; return calloc( 1, size ); }
void *Hunk_AllocateTempMemory( size_t size ) { return calloc( 1, size ); }
void  Hunk_FreeTempMemory( void *p ) { free( p ); }
int   Hunk_MemoryRemaining( void ) { return 0x70000000; }

// systemCall stub — interp path invokes this for negative call targets.
// Today only TRAP_SQRT is exercised by the fuzzer; the JIT inlines
// TRAP_SQRT as a direct fsqrts on FPR with no syscall, so the stub
// must match exactly.  Returns sqrtf(args[1]) reinterpreted as int32.
static intptr_t vmfuzz_systemCall( intptr_t *args )
{
	switch ( args[0] ) {
		case TRAP_SQRT: {
			union { float f; int32_t i; } u;
			u.i = (int32_t)args[1];
			u.f = sqrtf( u.f );
			return (intptr_t)u.i;
		}
		default:
			return 0;
	}
}


// dummy cvars — vm.c references com_developer + vm_rtChecks as engine globals
static cvar_t stub_cvar_zero = { 0 };
static cvar_t stub_cvar_rtchecks = { 0 };  // .integer set in main() to 15
cvar_t *com_developer = &stub_cvar_zero;
extern cvar_t *vm_rtChecks;
int fs_lastPakIndex = -1;
cvar_t *Cvar_Get( const char *name, const char *value, int flags )
{
	(void)name; (void)value; (void)flags;
	return &stub_cvar_zero;
}
int Cvar_VariableIntegerValue( const char *name ) { (void)name; return 0; }

void Cmd_AddCommand( const char *name, void (*fn)(void) ) { (void)name; (void)fn; }
int  Cmd_Argc( void ) { return 0; }
const char *Cmd_Argv( int i ) { (void)i; return ""; }

void FS_FCloseFile( fileHandle_t f ) { (void)f; }
int FS_FOpenFileRead( const char *qpath, fileHandle_t *file, qboolean unique ) {
	(void)qpath; (void)unique;
	*file = FS_INVALID_HANDLE;
	return -1;
}
int FS_ReadFile( const char *qpath, void **buffer ) {
	(void)qpath;
	*buffer = NULL;
	return -1;
}
void FS_FreeFile( void *buffer ) { free( buffer ); }
int FS_Read( void *buf, int len, fileHandle_t f ) {
	(void)buf; (void)len; (void)f;
	return 0;
}
void *FS_LoadLibrary( const char *name ) { (void)name; return NULL; }

void *Sys_LoadFunction( void *handle, const char *name ) {
	(void)handle; (void)name;
	return NULL;
}
void Sys_UnloadLibrary( void *handle ) { (void)handle; }
FILE *Sys_FOpen( const char *ospath, const char *mode ) {
	return fopen( ospath, mode );
}


// =========================================================================
// QVM program builder
// =========================================================================
//
// In-memory format mirroring qfiles.h vmHeader_t:
//   [vmHeader_t (32 bytes)]
//   [code bytes]   (variable-length op encoding)
//   [data bytes]   (initialized data + bss zero-fill)

#define MAX_OPS         192
#define MAX_CODE_BYTES  (MAX_OPS * 6)
#define DATA_BYTES      256
// F1 frame layout (LCC-conformant):
//   offset 8           = accumulator (read/written via LOCAL+LOAD4 / LOCAL+STORE4)
//   offset 12          = scratch (used by the JUMP-skip island to keep
//                        opStack=0 across the skipped block)
//   offsets 16..60     = dynamic locals for the unsafe-memory island
// Total frame size 64 leaves headroom; islands never run beyond it.
#define FRAME_BYTES     64
#define ACC_OFFS        8
#define SCRATCH_OFFS    12

typedef struct {
	uint8_t   op;
	int32_t   value;
	int       has_value;   // 0 = no operand, 1 = 4-byte, 2 = 1-byte (OP_ARG)
} fuzz_op_t;

#define MAX_CALL_PATCHES 16

typedef struct {
	fuzz_op_t ops[MAX_OPS];
	int       n;
	int       sim_stack;   // simulated opstack depth at end of building (4-byte slots)
	int       call_patches[MAX_CALL_PATCHES];  // indices of OP_CONST whose value needs patching to F2's ip
	int       n_call_patches;
} fuzz_prog_t;


static void fp_push( fuzz_prog_t *p, uint8_t op, int has_value, int32_t value )
{
	fuzz_op_t *o;
	if ( p->n >= MAX_OPS ) {
		fprintf( stderr, "fp_push: program too long\n" );
		exit( 2 );
	}
	o = &p->ops[p->n++];
	o->op = op;
	o->has_value = has_value;
	o->value = value;
}

// Sample a "spicy" 32-bit value — biased toward the boundary cases
// most likely to expose immediate-encoding bugs in the JIT.
static int32_t spicy_value( void )
{
	const int32_t cands[] = {
		0, 1, -1, 2, -2, 3, -3, 4, -4, 7, -7, 8, -8,
		15, -15, 16, -16, 31, -31, 32, -32, 63, 127, -128,
		255, -255, 256, -256, 1023, -1024, 2047, -2048,
		4095, -4096, 8191, -8192, 16383, -16384,
		32767, -32768, 32768, -32769, 65535, -65536,
		131072, -131072, 16777215, -16777216,
		0x7FFFFFFF, (int32_t)0x80000000, (int32_t)0xFFFFFFFF,
		0x00010000, (int32_t)0xFFFF0000, 0x00100000,
	};
	const int n = (int)( sizeof(cands) / sizeof(cands[0]) );
	if ( ( rand() & 7 ) == 0 ) {
		// full-random tail to keep coverage broad
		return (int32_t)( ( (uint32_t)rand() << 16 ) ^ (uint32_t)rand() );
	}
	return cands[ rand() % n ];
}


// Pick a non-zero divisor for DIV/MOD (zero behaviour is intentionally
// not contracted between backends).
static int32_t spicy_nonzero_value( void )
{
	int32_t v;
	do { v = spicy_value(); } while ( v == 0 );
	return v;
}

// Op-mix knob: VMFUZZ_NOBRANCH=1 removes conditional branches and the
// JUMP table they imply, so the linear-only paths can be fuzzed in
// isolation while a known branch-class bug is outstanding.
static int g_nobranch = 0;


// Build an LCC-conformant program of the shape:
//   ENTER <frame>
//   LOCAL acc; CONST <init>; STORE4       ; initialise accumulator in local
//   { random body island } * k            ; each runs from opStack=0 to opStack=0
//   LOCAL acc; LOAD4                      ; push final accumulator
//   LEAVE <frame>                         ; returns accumulator
//   PUSH ; LEAVE <frame>                  ; QVM end-of-proc marker
//
// The accumulator lives in the F1 frame at offset ACC_OFFS, NOT on the
// opStack across iterations.  This matches LCC's emission pattern: real
// QVM bytecode produced by q3asm always reaches statement boundaries
// (and therefore every branch source / target) with opStack = 0.  An
// earlier version of this fuzzer carried the accumulator on opStack;
// that left a cached TYPE_CONST slot below the cmp operands at every
// branch, which is a configuration LCC never produces and which the
// JIT's lazy materialisation does not necessarily handle.
//
// Islands that update the accumulator follow the canonical LCC lvalue
// pattern:
//     LOCAL ACC_OFFS            ; push lvalue address    (opStack=4)
//     <expression that pushes the new value on top>      (opStack=8)
//     STORE4                    ; *addr = value          (opStack=0)
// Islands that don't touch the accumulator (BLOCK_COPY, OP_JUMP) just
// run their own opStack=0-balanced sequence.
//
// If any island generates an OP_CALL to a placeholder ip, a self-
// recursive helper F2 is appended after F1's end-of-proc marker and
// the placeholders are patched to its entry ip.
static void build_program( fuzz_prog_t *p )
{
	static const uint8_t bin_ops[] = {
		OP_ADD, OP_SUB, OP_MULI, OP_MULU,
		OP_BAND, OP_BOR, OP_BXOR,
	};
	static const uint8_t div_ops[] = {
		OP_DIVI, OP_DIVU, OP_MODI, OP_MODU,
	};
	static const uint8_t shift_ops[] = { OP_LSH, OP_RSHI, OP_RSHU };
	static const uint8_t cmp_ops[] = {
		OP_EQ, OP_NE,
		OP_LTI, OP_LEI, OP_GTI, OP_GEI,
		OP_LTU, OP_LEU, OP_GTU, OP_GEU,
	};
	static const uint8_t unary_ops[] = { OP_NEGI, OP_BCOM, OP_SEX8, OP_SEX16 };

	int k = 1 + rand() % 6;
	int i;

	p->n = 0;
	p->sim_stack = 0;
	p->n_call_patches = 0;

	fp_push( p, OP_ENTER, 1, FRAME_BYTES );
	// Initialise the accumulator local: *(LOCAL ACC_OFFS) = spicy_value().
	fp_push( p, OP_LOCAL, 1, ACC_OFFS );
	fp_push( p, OP_CONST, 1, spicy_value() );
	fp_push( p, OP_STORE4, 0, 0 );
	// opStack = 0 at every island boundary from here on.

	for ( i = 0; i < k; i++ ) {
		int r = rand() % 100;
		uint8_t op;
		int32_t imm;

		if ( r < 45 ) {
			// binary op:  acc = acc <bop> imm
			op = bin_ops[ rand() % (int)( sizeof(bin_ops)/sizeof(bin_ops[0]) ) ];
			imm = spicy_value();
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );        // lvalue addr
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );        // rvalue addr
			fp_push( p, OP_LOAD4, 0, 0 );               // -> acc value
			fp_push( p, OP_CONST, 1, imm );
			fp_push( p, op,       0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
		} else if ( r < 60 ) {
			// shift:  acc = acc <shift> (rand 0..31)
			op = shift_ops[ rand() % 3 ];
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, OP_CONST, 1, rand() % 32 );
			fp_push( p, op,       0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
		} else if ( r < 75 ) {
			// DIV/MOD with non-zero divisor
			op = div_ops[ rand() % (int)( sizeof(div_ops)/sizeof(div_ops[0]) ) ];
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, OP_CONST, 1, spicy_nonzero_value() );
			fp_push( p, op,       0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
		} else if ( r < 80 ) {
			// unsafe memory island — dynamic address via arithmetic.
			// Stores `val` into dataBase[*local_n + off] at a randomly
			// chosen access width, then loads it back and combines with
			// the accumulator.  Each sub-step runs to opStack=0.
			int local_n = 16 + 4 * ( rand() % 12 );    // 16..60, avoids ACC/SCRATCH
			int32_t base = rand() % 64;
			int32_t off  = ( rand() % 32 ) * 4;
			int32_t val  = spicy_value();
			uint8_t bop = bin_ops[ rand() % (int)( sizeof(bin_ops)/sizeof(bin_ops[0]) ) ];
			int sz = rand() % 3;
			uint8_t store_op = (sz == 0) ? OP_STORE1 : (sz == 1) ? OP_STORE2 : OP_STORE4;
			uint8_t load_op  = (sz == 0) ? OP_LOAD1  : (sz == 1) ? OP_LOAD2  : OP_LOAD4;

			// *(LOCAL local_n) = base
			fp_push( p, OP_LOCAL,  1, local_n );
			fp_push( p, OP_CONST,  1, base );
			fp_push( p, OP_STORE4, 0, 0 );

			// dataBase[*local_n + off] = val
			fp_push( p, OP_LOCAL,  1, local_n );
			fp_push( p, OP_LOAD4,  0, 0 );
			fp_push( p, OP_CONST,  1, off );
			fp_push( p, OP_ADD,    0, 0 );
			fp_push( p, OP_CONST,  1, val );
			fp_push( p, store_op,  0, 0 );

			// acc = acc <bop> dataBase[*local_n + off]
			fp_push( p, OP_LOCAL,  1, ACC_OFFS );        // lvalue
			fp_push( p, OP_LOCAL,  1, ACC_OFFS );
			fp_push( p, OP_LOAD4,  0, 0 );               // rvalue acc
			fp_push( p, OP_LOCAL,  1, local_n );
			fp_push( p, OP_LOAD4,  0, 0 );               // base
			fp_push( p, OP_CONST,  1, off );
			fp_push( p, OP_ADD,    0, 0 );               // addr
			fp_push( p, load_op,   0, 0 );               // loaded value
			fp_push( p, bop,       0, 0 );               // combine
			fp_push( p, OP_STORE4, 0, 0 );
		} else if ( r < 82 ) {
			// CALL island — acc = acc <bop> F2(arg_n).
			// LCC pattern: lvalue addr below acc-load below ARG/CALL, so
			// the bop combines acc with F2's return on top.
			if ( p->n_call_patches < MAX_CALL_PATCHES ) {
				int32_t arg_n = rand() % 6;
				uint8_t bop = bin_ops[ rand() % (int)( sizeof(bin_ops)/sizeof(bin_ops[0]) ) ];
				fp_push( p, OP_LOCAL, 1, ACC_OFFS );    // lvalue
				fp_push( p, OP_LOCAL, 1, ACC_OFFS );
				fp_push( p, OP_LOAD4, 0, 0 );           // acc value
				fp_push( p, OP_CONST, 1, arg_n );
				fp_push( p, OP_ARG,   2, 8 );           // pass arg
				fp_push( p, OP_CONST, 1, 0 );           // F2 ip placeholder
				p->call_patches[ p->n_call_patches++ ] = p->n - 1;
				fp_push( p, OP_CALL,  0, 0 );           // ret on top
				fp_push( p, bop,      0, 0 );
				fp_push( p, OP_STORE4, 0, 0 );
			} else {
				// out of patch slots — emit a harmless acc-touching unary
				fp_push( p, OP_LOCAL, 1, ACC_OFFS );
				fp_push( p, OP_LOCAL, 1, ACC_OFFS );
				fp_push( p, OP_LOAD4, 0, 0 );
				fp_push( p, OP_NEGI,  0, 0 );
				fp_push( p, OP_STORE4, 0, 0 );
			}
		} else if ( r < 85 ) {
			// BLOCK_COPY island — pop-2, no push.  Doesn't touch acc.
			// Runs at opStack=0 boundary, same as LCC's emission for a
			// memcpy/struct-copy statement.
			int32_t src = rand() % 128;
			int32_t dst = 128 + ( rand() % 64 );
			int32_t count = 4 + 4 * ( rand() % 8 );
			fp_push( p, OP_CONST,  1, src );
			fp_push( p, OP_CONST,  1, dst );
			fp_push( p, OP_BLOCK_COPY, 1, count );
		} else if ( r < 90 ) {
			// float-arith island — acc = int( float(acc) <fop> fconst )
			static const int32_t float_bits[] = {
				0x3F800000, 0x40000000, 0x40400000, 0xBF800000,
				0x42480000, 0xC0000000, 0x3DCCCCCD, 0x447A0000,
				0x4F000000, 0x00000001,
			};
			static const uint8_t float_ops[] = {
				OP_ADDF, OP_SUBF, OP_MULF, OP_DIVF,
			};
			int32_t fbits = float_bits[ rand() % (int)( sizeof(float_bits)/sizeof(float_bits[0]) ) ];
			uint8_t fop = float_ops[ rand() % (int)( sizeof(float_ops)/sizeof(float_ops[0]) ) ];
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, OP_CVIF,  0, 0 );
			fp_push( p, OP_CONST, 1, fbits );
			fp_push( p, fop,      0, 0 );
			fp_push( p, OP_CVFI,  0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
		} else if ( r < 91 ) {
			// float-unary OP_NEGF
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, OP_CVIF,  0, 0 );
			fp_push( p, OP_NEGF,  0, 0 );
			fp_push( p, OP_CVFI,  0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
		} else if ( r < 92 ) {
			// TRAP_SQRT syscall — acc = acc <bop> sqrt(fbits)
			static const int32_t pos_float_bits[] = {
				0x3F800000, 0x40000000, 0x40400000, 0x42480000,
				0x447A0000, 0x3DCCCCCD, 0x00000000,
			};
			int32_t fbits = pos_float_bits[ rand() % (int)( sizeof(pos_float_bits)/sizeof(pos_float_bits[0]) ) ];
			uint8_t bop = bin_ops[ rand() % (int)( sizeof(bin_ops)/sizeof(bin_ops[0]) ) ];
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, OP_CONST, 1, fbits );
			fp_push( p, OP_ARG,   2, 8 );
			fp_push( p, OP_CONST, 1, ~TRAP_SQRT );
			fp_push( p, OP_CALL,  0, 0 );
			fp_push( p, bop,      0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
		} else if ( !g_nobranch && r < 94 ) {
			// OP_JUMP island — unconditional indirect jump skipping a
			// short opStack=0-balanced block.  Both the JUMP source and
			// the jump target sit at opStack=0, matching LCC.
			//
			//   CONST <target_ip>          ; opStack 0 -> 4
			//   JUMP                       ; opStack 4 -> 0
			//   LOCAL SCRATCH; CONST 0; STORE4    ; skipped, opStack 0 -> 0
			//   target_ip:                 ; opStack = 0
			fp_push( p, OP_CONST, 1, 0 );          // placeholder
			int jmp_idx = p->n - 1;
			fp_push( p, OP_JUMP,  0, 0 );
			fp_push( p, OP_LOCAL, 1, SCRATCH_OFFS );
			fp_push( p, OP_CONST, 1, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
			p->ops[jmp_idx].value = p->n;
		} else if ( !g_nobranch && r < 96 ) {
			// float-cmp branch — opStack=0 at both source and target.
			//   CONST a; CONST b; <fcmp> Ldst    ; pops 2 -> opStack 0
			//   <acc update via fop with c>      ; opStack 0 -> 0
			//   Ldst:                            ; opStack 0
			static const uint8_t fcmp_ops[] = {
				OP_EQF, OP_NEF, OP_LTF, OP_LEF, OP_GTF, OP_GEF,
			};
			static const int32_t float_bits[] = {
				0x3F800000, 0x40000000, 0x40400000, 0xBF800000,
				0x42480000, 0xC0000000, 0x3DCCCCCD, 0x447A0000,
				0x4F000000, 0x00000000,
			};
			uint8_t fop = fcmp_ops[ rand() % (int)( sizeof(fcmp_ops)/sizeof(fcmp_ops[0]) ) ];
			int32_t a = float_bits[ rand() % (int)( sizeof(float_bits)/sizeof(float_bits[0]) ) ];
			int32_t b = float_bits[ rand() % (int)( sizeof(float_bits)/sizeof(float_bits[0]) ) ];
			int32_t c = spicy_value();
			uint8_t bop = bin_ops[ rand() % (int)( sizeof(bin_ops)/sizeof(bin_ops[0]) ) ];
			fp_push( p, OP_CONST, 1, a );
			fp_push( p, OP_CONST, 1, b );
			fp_push( p, fop,      1, 0 );           // placeholder ip
			int cmp_idx = p->n - 1;
			// fall-through: acc = acc <bop> c
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, OP_CONST, 1, c );
			fp_push( p, bop,      0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
			p->ops[cmp_idx].value = p->n;            // target = next ip
		} else if ( !g_nobranch && r < 97 ) {
			// int-cmp branch — same shape as float-cmp branch.
			//   CONST a; CONST b; <cmp> Ldst     ; opStack 0
			//   <acc update via bop with c>      ; opStack 0
			//   Ldst:                            ; opStack 0
			op = cmp_ops[ rand() % (int)( sizeof(cmp_ops)/sizeof(cmp_ops[0]) ) ];
			int32_t a = spicy_value();
			int32_t b = spicy_value();
			int32_t c = spicy_value();
			uint8_t bop = bin_ops[ rand() % (int)( sizeof(bin_ops)/sizeof(bin_ops[0]) ) ];

			fp_push( p, OP_CONST, 1, a );
			fp_push( p, OP_CONST, 1, b );
			fp_push( p, op,       1, 0 );           // placeholder ip
			int cmp_idx = p->n - 1;
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, OP_CONST, 1, c );
			fp_push( p, bop,      0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
			p->ops[cmp_idx].value = p->n;
		} else {
			// unary op:  acc = <unary>(acc)
			op = unary_ops[ rand() % (int)( sizeof(unary_ops)/sizeof(unary_ops[0]) ) ];
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOCAL, 1, ACC_OFFS );
			fp_push( p, OP_LOAD4, 0, 0 );
			fp_push( p, op,       0, 0 );
			fp_push( p, OP_STORE4, 0, 0 );
		}
	}

	// Push final accumulator onto opStack, then return via LEAVE.
	// Validator requires the trailing PUSH; LEAVE end-of-proc marker.
	fp_push( p, OP_LOCAL, 1, ACC_OFFS );
	fp_push( p, OP_LOAD4, 0, 0 );
	fp_push( p, OP_LEAVE, 1, FRAME_BYTES );
	fp_push( p, OP_PUSH,  0, 0 );
	fp_push( p, OP_LEAVE, 1, FRAME_BYTES );
	p->sim_stack = 0;

	// If F1 generated any CALL islands, append F2 — a self-recursive
	// helper:  `int F2( int n ) { return n > 0 ? F2(n-1) + 1 : 100; }`.
	// Called with n=k from F1, returns 100+k.  Exercises call-stack
	// recursion, intermediate OP_LEAVE, and OP_GTI conditional branch.
	//
	// The intermediate LEAVE in each path (rather than OP_JUMP to a
	// shared end marker) is intentional: the validator's linear opstack
	// walker can't see OP_JUMP as a control-flow terminator, so jumping
	// past code with non-zero opstack would mismatch the GTI's target-
	// opstack check.  Intermediate LEAVE has stack -4 so the next ip
	// (the recursive case start) ends up with opstack=0 in the linear
	// walk, matching the GTI target requirement.
	if ( p->n_call_patches > 0 ) {
		const int F2_FRAME = 16;
		int f2_ip = p->n;
		fp_push( p, OP_ENTER,  1, F2_FRAME );
		// load arg n
		fp_push( p, OP_LOCAL,  1, F2_FRAME + 8 );
		fp_push( p, OP_LOAD4,  0, 0 );
		fp_push( p, OP_CONST,  1, 0 );
		// GTI L_recurse — if n > 0 branch (else fall through to base case)
		int gti_idx = p->n;
		fp_push( p, OP_GTI,    1, 0 );
		// base case (fall-through): return 100
		fp_push( p, OP_CONST,  1, 100 );
		fp_push( p, OP_LEAVE,  1, F2_FRAME );   // intermediate return
		// L_recurse: opstack=0 (linear walk continues here after the LEAVE)
		int l_rec_ip = p->n;
		fp_push( p, OP_LOCAL,  1, F2_FRAME + 8 );
		fp_push( p, OP_LOAD4,  0, 0 );
		fp_push( p, OP_CONST,  1, 1 );
		fp_push( p, OP_SUB,    0, 0 );          // n-1
		fp_push( p, OP_ARG,    2, 8 );          // pass n-1
		fp_push( p, OP_CONST,  1, f2_ip );      // recurse target
		fp_push( p, OP_CALL,   0, 0 );          // returns F2(n-1) on top
		fp_push( p, OP_CONST,  1, 1 );
		fp_push( p, OP_ADD,    0, 0 );          // F2(n-1) + 1
		fp_push( p, OP_LEAVE,  1, F2_FRAME );   // intermediate return
		fp_push( p, OP_PUSH,   0, 0 );
		fp_push( p, OP_LEAVE,  1, F2_FRAME );
		p->ops[gti_idx].value = l_rec_ip;
		// patch F1 call sites
		for ( int i = 0; i < p->n_call_patches; i++ ) {
			p->ops[ p->call_patches[i] ].value = f2_ip;
		}
	}
}


// Encode a fuzz_prog_t as on-disk QVM bytecode.  Returns total .qvm size.
static int encode_program( const fuzz_prog_t *p, byte **out_buf )
{
	byte *code, *cp;
	byte *buf;
	int code_max = MAX_CODE_BYTES;
	int total;
	vmHeader_t *h;
	int i;

	code = (byte*)calloc( 1, code_max );
	cp = code;
	for ( i = 0; i < p->n; i++ ) {
		const fuzz_op_t *o = &p->ops[i];
		*cp++ = o->op;
		if ( o->has_value == 1 ) {
			int32_t v = o->value;
			memcpy( cp, &v, 4 );
			cp += 4;
		} else if ( o->has_value == 2 ) {
			*cp++ = (byte)( o->value & 0xFF );
		}
	}
	int code_len = (int)( cp - code );

	total = sizeof( vmHeader_t ) + code_len + DATA_BYTES;
	buf = (byte*)calloc( 1, total );
	h = (vmHeader_t*)buf;
	h->vmMagic = VM_MAGIC;
	h->instructionCount = p->n;
	h->codeOffset = sizeof( vmHeader_t );
	h->codeLength = code_len;
	h->dataOffset = sizeof( vmHeader_t ) + code_len;
	h->dataLength = 0;
	h->litLength = 0;
	h->bssLength = DATA_BYTES;

	memcpy( buf + h->codeOffset, code, code_len );
	free( code );

	*out_buf = buf;
	return total;
}


// =========================================================================
// VM bring-up (interp + JIT) and execution
// =========================================================================

#define ROUND_POW2(x) ({ uint32_t _v = (uint32_t)(x), _r = 1; \
	while (_r < _v) _r <<= 1; _r; })

static qboolean run_one( const byte *qvm, int qvm_len, vmInterpret_t mode,
                         int32_t *out_result )
{
	vm_t vm;
	vmHeader_t *header;
	uint32_t data_alloc;
	int32_t args[1] = { 0 };

	(void)qvm_len;
	memset( &vm, 0, sizeof( vm ) );
	vm.name = "fuzz";
	vm.systemCall = vmfuzz_systemCall;
	header = (vmHeader_t*)qvm;

	vm.exactDataLength = header->dataLength + header->litLength + header->bssLength;
	vm.dataLength = vm.exactDataLength;
	if ( vm.dataLength < PROGRAM_STACK_SIZE ) {
		vm.dataLength = PROGRAM_STACK_SIZE;
	}
	vm.dataLength += PROGRAM_STACK_EXTRA;
	vm.programStackExtra = PROGRAM_STACK_EXTRA;

	uint32_t padded = 1;
	while ( padded < vm.dataLength ) padded <<= 1;
	vm.dataMask = padded - 1;
	data_alloc = padded + VM_DATA_GUARD_SIZE;

	vm.dataBase = (byte*)mmap( NULL, data_alloc,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 );
	if ( vm.dataBase == MAP_FAILED ) {
		fprintf( stderr, "mmap dataBase failed\n" );
		return qfalse;
	}
	memset( vm.dataBase, 0, data_alloc );
	vm.dataAlloc = data_alloc;

	// copy initialized data (data + lit) into dataBase
	memcpy( vm.dataBase, (byte*)header + header->dataOffset,
		header->dataLength + header->litLength );

	vm.instructionCount = header->instructionCount;
	vm.programStack = vm.dataMask + 1;
	vm.stackBottom = vm.programStack - PROGRAM_STACK_SIZE - vm.programStackExtra;
	if ( getenv("VMFUZZ_DEBUG") ) {
		fprintf( stderr, "[fuzz] dataLength=%u dataMask=0x%x dataAlloc=%u programStack=%d stackBottom=%d\n",
			vm.dataLength, vm.dataMask, data_alloc, vm.programStack, vm.stackBottom );
	}

	if ( mode == VMI_COMPILED ) {
		if ( !VM_Compile( &vm, header ) ) {
			fprintf( stderr, "VM_Compile failed\n" );
			munmap( vm.dataBase, data_alloc );
			return qfalse;
		}
		if ( getenv("VMFUZZ_DEBUG") ) {
			uint32_t *cb = (uint32_t*)vm.codeBase.ptr;
			int n = vm.codeLength / 4;
			fprintf( stderr, "[fuzz] codeBase=%p codeLength=%u  insns:\n", vm.codeBase.ptr, vm.codeLength );
			for ( int i = 0; i < n; i++ ) {
				fprintf( stderr, "  +0x%03x: %08x\n", i * 4, cb[i] );
			}
		}
		*out_result = VM_CallCompiled( &vm, 0, args );
		if ( getenv("VMFUZZ_DEBUG") ) {
			fprintf( stderr, "[fuzz] JIT returned %d (0x%x)  programStack after=%d\n",
				*out_result, (uint32_t)*out_result, vm.programStack );
		}
	} else {
		if ( !VM_PrepareInterpreter2( &vm, header ) ) {
			fprintf( stderr, "VM_PrepareInterpreter2 failed\n" );
			munmap( vm.dataBase, data_alloc );
			return qfalse;
		}
		*out_result = VM_CallInterpreted2( &vm, 0, args );
	}

	munmap( vm.dataBase, data_alloc );
	if ( vm.codeBase.ptr ) {
		munmap( vm.codeBase.ptr, vm.codeSize );
	}
	return qtrue;
}


// =========================================================================
// Diff reporter
// =========================================================================

static const char *opname_of( int op )
{
	extern const char *opname[256];
	return opname[op] ? opname[op] : "?";
}

static void dump_program( FILE *f, const fuzz_prog_t *p )
{
	int i;
	for ( i = 0; i < p->n; i++ ) {
		const fuzz_op_t *o = &p->ops[i];
		if ( o->has_value ) {
			fprintf( f, "  %3d  %-10s  %d (0x%x)\n", i, opname_of(o->op), o->value, (uint32_t)o->value );
		} else {
			fprintf( f, "  %3d  %s\n", i, opname_of(o->op) );
		}
	}
}

static void save_failing( unsigned seed, const fuzz_prog_t *p,
                          const byte *qvm, int qvm_len )
{
	char path[256];
	FILE *fb, *fl;
	snprintf( path, sizeof( path ), "/tmp/vmfuzz-fail-%u.qvm", seed );
	fb = fopen( path, "wb" );
	if ( fb ) { fwrite( qvm, 1, qvm_len, fb ); fclose( fb ); }
	snprintf( path, sizeof( path ), "/tmp/vmfuzz-fail-%u.log", seed );
	fl = fopen( path, "w" );
	if ( fl ) { dump_program( fl, p ); fclose( fl ); }
}


// =========================================================================
// main
// =========================================================================

// Hand-crafted minimal LTI branch test for isolating JIT-vs-fuzzer-gen
static int unit_test_lti_branch( void )
{
	fuzz_prog_t p = {0};
	byte *qvm = NULL;
	int qvm_len;
	int32_t r_i = 0, r_j = 0;
	qboolean ok;

	// Test 1: LTI-taken — int acc = 100; if (1 < 2) {} else acc += 999; return acc;
	// LCC pattern: acc lives in local 8; branch sources sit at opStack=0.
	fp_push( &p, OP_ENTER,  1, 16 );
	fp_push( &p, OP_LOCAL,  1, 8 );    // acc = 100
	fp_push( &p, OP_CONST,  1, 100 );
	fp_push( &p, OP_STORE4, 0, 0 );
	fp_push( &p, OP_CONST,  1, 1 );    // cmp lhs
	fp_push( &p, OP_CONST,  1, 2 );    // cmp rhs
	fp_push( &p, OP_LTI,    1, 13 );   // 1<2 -> taken, skip acc += 999
	fp_push( &p, OP_LOCAL,  1, 8 );    // acc lvalue
	fp_push( &p, OP_LOCAL,  1, 8 );    // acc rvalue addr
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_CONST,  1, 999 );
	fp_push( &p, OP_ADD,    0, 0 );
	fp_push( &p, OP_STORE4, 0, 0 );
	fp_push( &p, OP_LOCAL,  1, 8 );    // ip 13 (LTI target): push acc, return
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	fp_push( &p, OP_PUSH,   0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	qvm_len = encode_program( &p, &qvm );

	ok = run_one( qvm, qvm_len, VMI_BYTECODE, &r_i );
	if ( !ok ) { fprintf( stderr, "unit: interp setup failed\n" ); free(qvm); return 1; }
	ok = run_one( qvm, qvm_len, VMI_COMPILED, &r_j );
	if ( !ok ) { fprintf( stderr, "unit: jit setup failed\n" ); free(qvm); return 1; }

	printf( "unit LTI-taken:       interp=%d  jit=%d  expected=100\n", r_i, r_j );
	free(qvm);

	// Test 2: LTI-fallthrough — same C source but cmp false; runs acc += 999.
	memset( &p, 0, sizeof(p) );
	fp_push( &p, OP_ENTER,  1, 16 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_CONST,  1, 100 );
	fp_push( &p, OP_STORE4, 0, 0 );
	fp_push( &p, OP_CONST,  1, 2 );    // 2 < 1 is false -> fall through
	fp_push( &p, OP_CONST,  1, 1 );
	fp_push( &p, OP_LTI,    1, 13 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_CONST,  1, 999 );
	fp_push( &p, OP_ADD,    0, 0 );
	fp_push( &p, OP_STORE4, 0, 0 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	fp_push( &p, OP_PUSH,   0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	qvm_len = encode_program( &p, &qvm );
	run_one( qvm, qvm_len, VMI_BYTECODE, &r_i );
	run_one( qvm, qvm_len, VMI_COMPILED, &r_j );
	printf( "unit LTI-fallthrough: interp=%d  jit=%d  expected=1099\n", r_i, r_j );
	free(qvm);

	// Test 3: linear program (no branch).  acc = 100 + 7 = 107.
	memset( &p, 0, sizeof(p) );
	fp_push( &p, OP_ENTER,  1, 16 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_CONST,  1, 100 );
	fp_push( &p, OP_STORE4, 0, 0 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_CONST,  1, 7 );
	fp_push( &p, OP_ADD,    0, 0 );
	fp_push( &p, OP_STORE4, 0, 0 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	fp_push( &p, OP_PUSH,   0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	qvm_len = encode_program( &p, &qvm );
	run_one( qvm, qvm_len, VMI_BYTECODE, &r_i );
	run_one( qvm, qvm_len, VMI_COMPILED, &r_j );
	printf( "unit linear:          interp=%d  jit=%d  expected=107\n", r_i, r_j );
	free(qvm);

	// Test 4: multi-function CALL/RET/ARG.
	//   F1: int acc = F2(42) + 5; return acc;     (-> 147)
	//   F2: int n -> return n + 100;              (-> 142)
	memset( &p, 0, sizeof(p) );
	fp_push( &p, OP_ENTER,  1, 16 );    // F1 frame, acc at offset 8
	fp_push( &p, OP_LOCAL,  1, 8 );     // acc lvalue
	fp_push( &p, OP_CONST,  1, 42 );    // arg n
	fp_push( &p, OP_ARG,    2, 8 );
	fp_push( &p, OP_CONST,  1, 0 );     // F2 ip — patched below
	int f1_call_const = p.n - 1;
	fp_push( &p, OP_CALL,   0, 0 );
	fp_push( &p, OP_CONST,  1, 5 );
	fp_push( &p, OP_ADD,    0, 0 );     // F2(42) + 5
	fp_push( &p, OP_STORE4, 0, 0 );
	fp_push( &p, OP_LOCAL,  1, 8 );
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	fp_push( &p, OP_PUSH,   0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	p.ops[f1_call_const].value = p.n;   // F2 starts here
	fp_push( &p, OP_ENTER,  1, 16 );
	fp_push( &p, OP_LOCAL,  1, 24 );    // arg n at frame_size + 8
	fp_push( &p, OP_LOAD4,  0, 0 );
	fp_push( &p, OP_CONST,  1, 100 );
	fp_push( &p, OP_ADD,    0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	fp_push( &p, OP_PUSH,   0, 0 );
	fp_push( &p, OP_LEAVE,  1, 16 );
	qvm_len = encode_program( &p, &qvm );
	run_one( qvm, qvm_len, VMI_BYTECODE, &r_i );
	run_one( qvm, qvm_len, VMI_COMPILED, &r_j );
	printf( "unit CALL/ARG:        interp=%d  jit=%d  expected=147\n", r_i, r_j );
	free(qvm);

	return 0;
}


int main( int argc, char **argv )
{
	unsigned base_seed = (unsigned)time( NULL ) ^ (unsigned)getpid();
	int n_iter = 1000;
	int fails = 0;
	int i;

	if ( argc > 1 && strcmp( argv[1], "--unit" ) == 0 ) {
		const char *e = getenv( "VMFUZZ_RTCHECKS" );
		stub_cvar_rtchecks.integer = e ? atoi(e) : 15;
		vm_rtChecks = &stub_cvar_rtchecks;
		return unit_test_lti_branch();
	}

	if ( argc > 1 ) base_seed = (unsigned)strtoul( argv[1], NULL, 0 );
	if ( argc > 2 ) n_iter = atoi( argv[2] );

	// Engine cvar: enable all runtime checks (mirrors stock default).
	// Set VMFUZZ_RTCHECKS=0 to disable for debugging stack-check trips.
	{
		const char *e = getenv( "VMFUZZ_RTCHECKS" );
		stub_cvar_rtchecks.integer = e ? atoi(e) : 15;
	}
	vm_rtChecks = &stub_cvar_rtchecks;
	if ( getenv( "VMFUZZ_NOBRANCH" ) ) g_nobranch = 1;

	printf( "vmfuzz: seed=%u iter=%d\n", base_seed, n_iter );

	for ( i = 0; i < n_iter; i++ ) {
		unsigned seed = base_seed + i;
		fuzz_prog_t prog;
		byte *qvm = NULL;
		int qvm_len;
		int32_t r_interp = 0, r_jit = 0;
		qboolean ok_i, ok_j;

		srand( seed );
		build_program( &prog );
		qvm_len = encode_program( &prog, &qvm );

		ok_i = run_one( qvm, qvm_len, VMI_BYTECODE, &r_interp );
		ok_j = run_one( qvm, qvm_len, VMI_COMPILED, &r_jit );

		if ( !ok_i || !ok_j ) {
			fprintf( stderr, "[%u] backend setup failed (interp=%d jit=%d)\n",
				seed, ok_i, ok_j );
			save_failing( seed, &prog, qvm, qvm_len );
			fails++;
		} else if ( r_interp != r_jit ) {
			fprintf( stderr, "[%u] DIVERGENCE  interp=%d (0x%x)  jit=%d (0x%x)\n",
				seed, r_interp, (uint32_t)r_interp, r_jit, (uint32_t)r_jit );
			dump_program( stderr, &prog );
			save_failing( seed, &prog, qvm, qvm_len );
			fails++;
		} else if ( (i % 100) == 0 ) {
			printf( "[%u] ok  result=%d\n", seed, r_interp );
		}

		free( qvm );
	}

	printf( "vmfuzz: done — %d/%d failing\n", fails, n_iter );
	return fails ? 1 : 0;
}
