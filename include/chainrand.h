/**
 * [chainrand-cpp]{@link https://github.com/chainrand/chainrand-cpp}
 *
 * @version 0.0.1
 * @author Kang Yue Sheng Benjamin [chainrand@gmail.com]
 * @copyright Kang Yue Sheng Benjamin 2021
 * @license MIT
 */
#ifndef chainrand_h
#define chainrand_h

#include <stdint.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/time.h>
#include <ctime>
#endif

// For clang, use -maes flag to enable hardware aes instructions
#if defined (__AES__) || defined (__PCLMUL__)
#include <wmmintrin.h>
#endif

#define DEF_CHAINRAND_NAMESPACE_BEGIN namespace chainrand {
#define DEF_CHAINRAND_NAMESPACE_END };

DEF_CHAINRAND_NAMESPACE_BEGIN

/// Class for generating cryptographically secure random numbers
/// deterministic for provably fair off-chain sampling.
///
/// The numbers are generated from the output bits of AES-256-CBC
/// encryption on an incrementing counter with the SHA-256
/// of the seed as the key.
class CRNG
{
	template <class T> static inline void _swap(T &a, T &b) { T t = b; b = a; a = t; }

	template <class T> static inline T _min(T a, T b) { return a < b ? a : b; }
	
	template <class T> static inline T _max(T a, T b) { return b < a ? a : b; }
	
	struct _sha256Context
	{
		uint8_t hash[32];
		uint8_t chunk[64];
		uint8_t chunkPos;
		size_t spaceLeft;
		size_t totalLen;
		uint32_t h[8];
	};
	
	static inline uint32_t _rotr(uint32_t value, unsigned count)
	{
		return value >> count | value << (32 - count);
	}
	
	static void _sha256Consume(uint32_t *h, const uint8_t *p)
	{
		int i, j;
		uint32_t ah[8];
		
		for (i = 0; i < 8; i++)
			ah[i] = h[i];
		
		uint32_t w[16];
		
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 16; j++) {
				if (i == 0) {
					w[j] =
					(uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
					p += 4;
				} else {
					const uint32_t s0 = _rotr(w[(j + 1) & 0xf], 7) ^ _rotr(w[(j + 1) & 0xf], 18) ^
					(w[(j + 1) & 0xf] >> 3);
					const uint32_t s1 = _rotr(w[(j + 14) & 0xf], 17) ^
					_rotr(w[(j + 14) & 0xf], 19) ^ (w[(j + 14) & 0xf] >> 10);
					w[j] = w[j] + s0 + w[(j + 9) & 0xf] + s1;
				}
				const uint32_t s1 = _rotr(ah[4], 6) ^ _rotr(ah[4], 11) ^ _rotr(ah[4], 25);
				const uint32_t ch = (ah[4] & ah[5]) ^ (~ah[4] & ah[6]);
				
				static const uint32_t k[] = {
					0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
					0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
					0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
					0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
					0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
					0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
					0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
					0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
					0xc67178f2};
				
				const uint32_t temp1 = ah[7] + s1 + ch + k[i << 4 | j] + w[j];
				const uint32_t s0 = _rotr(ah[0], 2) ^ _rotr(ah[0], 13) ^ _rotr(ah[0], 22);
				const uint32_t maj = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
				const uint32_t temp2 = s0 + maj;
				
				ah[7] = ah[6];
				ah[6] = ah[5];
				ah[5] = ah[4];
				ah[4] = ah[3] + temp1;
				ah[3] = ah[2];
				ah[2] = ah[1];
				ah[1] = ah[0];
				ah[0] = temp1 + temp2;
			}
		}
		
		for (i = 0; i < 8; i++)
			h[i] += ah[i];
	}
	
	static void _sha256Init(_sha256Context &ctx)
	{
		for (int i = 0; i < 32; ++i)
			ctx.hash[i] = 0;
		
		ctx.chunkPos = 0;
		ctx.spaceLeft = 64;
		ctx.totalLen = 0;
		
		ctx.h[0] = 0x6a09e667;
		ctx.h[1] = 0xbb67ae85;
		ctx.h[2] = 0x3c6ef372;
		ctx.h[3] = 0xa54ff53a;
		ctx.h[4] = 0x510e527f;
		ctx.h[5] = 0x9b05688c;
		ctx.h[6] = 0x1f83d9ab;
		ctx.h[7] = 0x5be0cd19;
	}
	
	static void _sha256Write(_sha256Context &ctx, const void *data, size_t len)
	{
		ctx.totalLen += len;
		
		const uint8_t *p = (const uint8_t *) data;
		
		while (len > 0) {
			if (ctx.spaceLeft == 64 && len >= 64) {
				_sha256Consume(ctx.h, p);
				len -= 64;
				p += 64;
				continue;
			}
			const size_t consumedLen = len < ctx.spaceLeft ? len : ctx.spaceLeft;
			memcpy(ctx.chunk + ctx.chunkPos, p, consumedLen);
			ctx.spaceLeft -= consumedLen;
			len -= consumedLen;
			p += consumedLen;
			if (ctx.spaceLeft == 0) {
				_sha256Consume(ctx.h, ctx.chunk);
				ctx.chunkPos = 0;
				ctx.spaceLeft = 64;
			} else {
				ctx.chunkPos += consumedLen;
			}
		}
	}
	
	static void _sha256Close(_sha256Context &ctx)
	{
		uint8_t *pos = ctx.chunk + ctx.chunkPos;
		size_t spaceLeft = ctx.spaceLeft;
		uint32_t *const h = ctx.h;
		
		*pos++ = 0x80;
		--spaceLeft;
		
		const uint8_t totalLenLen = 8;
		
		if (spaceLeft < totalLenLen) {
			memset(pos, 0x00, spaceLeft);
			_sha256Consume(h, ctx.chunk);
			pos = ctx.chunk;
			spaceLeft = 64;
		}
		const size_t left = spaceLeft - totalLenLen;
		memset(pos, 0x00, left);
		pos += left;
		size_t len = ctx.totalLen;
		pos[7] = (uint8_t)(len << 3);
		len >>= 5;
		int i, j;
		for (i = 6; i >= 0; --i) {
			pos[i] = (uint8_t)len;
			len >>= 8;
		}
		_sha256Consume(h, ctx.chunk);
		uint8_t *const hash = ctx.hash;
		for (i = 0, j = 0; i < 8; i++) {
			hash[j++] = (uint8_t)(h[i] >> 24);
			hash[j++] = (uint8_t)(h[i] >> 16);
			hash[j++] = (uint8_t)(h[i] >> 8);
			hash[j++] = (uint8_t)h[i];
		}
	}
	
	// AES ode adapted from https://github.com/kokke/tiny-AES-c (unlicense)
	static inline uint8_t _sBoxValue(size_t i)
	{
		static const uint8_t a[256] = {
			//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
		return a[i];
	}
	
	static inline void _keyExpansion(uint8_t* roundKey, const uint8_t* key)
	{
		static const uint8_t rCon[11] = {
			0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
		};
		
		int i, j, k;
		uint8_t tempa[4];
		
		for (i = 0; i < 8; ++i) {
			roundKey[i*4+0] = key[i*4+0];
			roundKey[i*4+1] = key[i*4+1];
			roundKey[i*4+2] = key[i*4+2];
			roundKey[i*4+3] = key[i*4+3];
		}
		
		for (i = 8; i < 4 * (14 + 1); ++i) {
			k = (i - 1) * 4;
			tempa[0] = roundKey[k+0];
			tempa[1] = roundKey[k+1];
			tempa[2] = roundKey[k+2];
			tempa[3] = roundKey[k+3];
			
			if (i % 8 == 0) {
				const uint8_t u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;

				tempa[0] = _sBoxValue(tempa[0]);
				tempa[1] = _sBoxValue(tempa[1]);
				tempa[2] = _sBoxValue(tempa[2]);
				tempa[3] = _sBoxValue(tempa[3]);
				
				tempa[0] = tempa[0] ^ rCon[i/8];
			}
			if (i % 8 == 4) {
				tempa[0] = _sBoxValue(tempa[0]);
				tempa[1] = _sBoxValue(tempa[1]);
				tempa[2] = _sBoxValue(tempa[2]);
				tempa[3] = _sBoxValue(tempa[3]);
			}
			
			j = i * 4; k = (i - 8) * 4;
			roundKey[j+0] = roundKey[k+0] ^ tempa[0];
			roundKey[j+1] = roundKey[k+1] ^ tempa[1];
			roundKey[j+2] = roundKey[k+2] ^ tempa[2];
			roundKey[j+3] = roundKey[k+3] ^ tempa[3];
		}
	}
	
	static inline void _addRoundKey(uint8_t round, uint8_t* state, const uint8_t* roundKey)
	{
		for (int i = 0; i < 16; ++i)
			state[i] ^= roundKey[round * 16 + i];
	}
	
	static inline void _subBytes(uint8_t* state)
	{
		for (int i = 0; i < 16; ++i)
			state[i] = _sBoxValue(state[i]);
	}
	
	static inline void _shiftRows(uint8_t* state)
	{
		uint8_t temp;
		
		temp         = state[0*4+1];
		state[0*4+1] = state[1*4+1];
		state[1*4+1] = state[2*4+1];
		state[2*4+1] = state[3*4+1];
		state[3*4+1] = temp;
		
		temp         = state[0*4+2];
		state[0*4+2] = state[2*4+2];
		state[2*4+2] = temp;
		
		temp         = state[1*4+2];
		state[1*4+2] = state[3*4+2];
		state[3*4+2] = temp;
		
		temp         = state[0*4+3];
		state[0*4+3] = state[3*4+3];
		state[3*4+3] = state[2*4+3];
		state[2*4+3] = state[1*4+3];
		state[1*4+3] = temp;
	}
	
	static inline uint8_t xtime(uint8_t x)
	{
		return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
	}
	
	static inline void _mixColumns(uint8_t* state)
	{
		uint8_t i, tmp, tm, t;
		for (i = 0; i < 4; ++i) {
			t   = state[i*4+0];
			tmp = state[i*4+0] ^ state[i*4+1] ^ state[i*4+2] ^ state[i*4+3] ;
			tm  = state[i*4+0] ^ state[i*4+1] ; tm = xtime(tm);  state[i*4+0] ^= tm ^ tmp ;
			tm  = state[i*4+1] ^ state[i*4+2] ; tm = xtime(tm);  state[i*4+1] ^= tm ^ tmp ;
			tm  = state[i*4+2] ^ state[i*4+3] ; tm = xtime(tm);  state[i*4+2] ^= tm ^ tmp ;
			tm  = state[i*4+3] ^ t ;            tm = xtime(tm);  state[i*4+3] ^= tm ^ tmp ;
		}
	}
	
#if defined (__AES__) || defined (__PCLMUL__)
#if defined(__GNUC__)
#define AES_ALIGNED_START
#define AES_ALIGNED_END __attribute__((aligned(16)))
#else
#define AES_ALIGNED_START __declspec(align(16))
#define AES_ALIGNED_END
#endif
#else
#define AES_ALIGNED_START
#define AES_ALIGNED_END
#endif
	
	AES_ALIGNED_START struct _alignedData {
		uint8_t roundKey[240];
		uint8_t iv[16];
		uint8_t counter[16], buf[16];
		size_t bufOffset, inited;
		
		double gaussSpare;
		bool gaussHasSpare;
	} AES_ALIGNED_END;
	
	_alignedData _;
	
#undef AES_ALIGNED_START
#undef AES_ALIGNED_END
	
	inline void _genNextBlock()
	{
		memcpy(_.buf, _.counter, 16);

		_addRoundKey(0, _.buf, _.iv);
#if defined (__AES__) || defined (__PCLMUL__)
		__m128i mBuf, mRoundKey;
		mBuf = _mm_load_si128((__m128i*) _.buf);
		mRoundKey = _mm_load_si128((__m128i*) _.roundKey);
		mBuf = _mm_xor_si128(mBuf, mRoundKey);
		for (uint8_t round = 1; round < 14; ++round) {
			mRoundKey = _mm_load_si128((__m128i*) (_.roundKey + (round * 16)));
			mBuf = _mm_aesenc_si128(mBuf, mRoundKey);
		}
		mRoundKey = _mm_load_si128((__m128i*) (_.roundKey + (14 * 16)));
		mBuf = _mm_aesenclast_si128(mBuf, mRoundKey);
		_mm_store_si128((__m128i*) _.buf, mBuf);
#else
		_addRoundKey(0, _.buf, _.roundKey);
		for (uint8_t round = 1; round < 14; ++round) {
			_shiftRows(_.buf);
			_subBytes(_.buf);
			_mixColumns(_.buf);
			_addRoundKey(round, _.buf, _.roundKey);
		}
		_shiftRows(_.buf);
		_subBytes(_.buf);
		_addRoundKey(14, _.buf, _.roundKey);
#endif
		memcpy(_.iv, _.buf, 16);
		
		for (int i = 0; i < 16; ++i) {
			if (_.counter[i] < 255) {
				++_.counter[i];
				break;
			}
			_.counter[i] = 0;
		}
	}
	
	template <class Str>
	void _init(Str seed)
	{
		_sha256Context ctx;
		_sha256Init(ctx);
		size_t seedLen = 0;
		while (seed[seedLen]) {
			seedLen++;
		}
		_sha256Write(ctx, &seed[0], seedLen);
		_sha256Close(ctx);
		
		_keyExpansion(_.roundKey, ctx.hash);
		memset(_.iv, 0, 16);
		memset(_.counter, 0, 16);
		_.bufOffset = 0;
		_.inited = 1;
		_.gaussHasSpare = 0;
	}
	
public:
	
	/// Constructor.
	/// The seed should be "base10(<RNG_VRF_RESULT>)" + "<RNG_SEED_KEY>".
	/// For development purposes, you can use any string as the seed.
	/// \param seed  The random seed string.
	template <class Str> inline CRNG(Str seed)
	{
		_init(seed);
		_.gaussHasSpare = 0;
	}
	
	inline CRNG() { _.inited = 0; _.gaussHasSpare = 0; }
	
	/// Returns a single uniform random number within [0, (1<<(sizeof(T)*8))-1].
	template <class T> inline T nextUint()
	{
		if (!_.inited) {
			_init("");
		}
		if (_.bufOffset + sizeof(T) > 16) {
			_.bufOffset = 0;
		}
		if (_.bufOffset == 0) {
			_genNextBlock();
		}
		
		T result = 0;
		for (int j = 0; j < sizeof(T); ++j) {
			result |= (T) _.buf[_.bufOffset + j] << (j * 8);
		}
		_.bufOffset += sizeof(T);
		return result;
	}

	/// Returns a single uniform random number within [0, 255].
	inline uint8_t nextUInt8()
	{
		return nextUint<uint8_t>();
	}

	/// Returns a single uniform random number within [0, 65535].
	inline uint16_t nextUInt16()
	{
		return nextUint<uint16_t>();
	}

	/// Returns a single uniform random number within [0, 4294967295].
	inline uint32_t nextUInt32()
	{
		return nextUint<uint32_t>();
	}

	/// Returns a single uniform random number within [0, 18446744073709551615].
	inline uint64_t nextUInt64()
	{
		return nextUint<uint64_t>();
	}
	
	/// Returns a single uniform random number within [0,1).
	/// The numbers are in multiples of 2**-24.
	inline double nextFloat()
	{
		return (nextUInt32() >> 8) / 16777216.f;
	}

	/// Returns a single uniform random number within [0,1).
	/// The numbers are in multiples of 2**-53.
	inline double nextDouble()
	{
		return (nextUInt64() >> 11) / 9007199254740992.0;
	}
	
	/// Returns a single uniform random number within [0,1).
	/// The numbers are in multiples of 2**-53.
	inline double operator() ()
	{
		return nextDouble();
	}

	/// Returns a single uniform random number within [0,1).
	/// The numbers are in multiples of 2**-53.
	inline double random()
	{
		return nextDouble();
	}

	/// Returns a random integer uniformly distributed in [start, stop).
	/// The integers are spaced with intervals of abs(step).
	/// \param start  The lower/upper bound.
	/// \param stop  The upper/lower bound.
	/// \returns A random integer uniformly distributed in [start, stop).
	inline int64_t randrange(int64_t start, int64_t stop, int64_t step)
	{
		int64_t d = stop - start, t;
		if (step == 0) step = 1;
		if (d * step < 0) step = -step;
		t = d / step;
		return start + (int64_t)((t < 0 ? -t : t) * random()) * step;
	}

	/// Returns a random integer uniformly distributed in [start, stop).
	/// \param start  The lower/upper bound.
	/// \param stop  The upper/lower bound.
	/// \returns A random integer uniformly distributed in [start, stop).
	inline int64_t randrange(int64_t start, int64_t stop)
	{
		return randrange(start, stop, stop < start ? -1 : 1);
	}

	/// Returns a random integer uniformly distributed in [start, stop).
	/// This is equivalent to randrange(0, stop).
	/// \param stop  The upper/lower bound.
	/// \returns A random integer uniformly distributed in [start, stop).
	inline int64_t randrange(int64_t stop)
	{
		return randrange(0, stop);
	}
	
	/// Returns a random integer uniformly distributed in [a, b].
	/// If b < a, they will be swapped internally.
	/// \param a  The lower/upper bound.
	/// \param b  The upper/lower bound.
	/// \returns A random integer uniformly distributed in [a, b]
	inline int64_t randint(int64_t a, int64_t b)
	{
		if (b < a) _swap(a, b);
		return a + (b - a + 1) * random();
	}

	/// Returns a random integer uniformly distributed in [0, b].
	/// This is equivalent to randint(0, b).
	/// \param b  The upper/lower bound.
	/// \returns A random integer uniformly distributed in [0, b]
	inline int64_t randint(int64_t b)
	{
		return randint(0, b);
	}

	/// Shuffles the elements in-place.
	/// \param begin[in/out] An iterator to the start of the sequence.
	/// \param end[in/out]   An iterator to the end of the sequence.
	template <class RandomAccessIterator>
	void shuffle(RandomAccessIterator begin, RandomAccessIterator end)
	{
		if (end <= begin) return;
		size_t n = end - begin, i, j;
		for (i = n - 1; i > 0; i--) {
			j = (i+1) * random();
			_swap(*(begin + i), *(begin + j));
		}
	}

	/// Shuffles the elements in-place.
	/// \param[in/out] v A vector/array-like container of elements.
	template <class Vector>
	void shuffle(Vector &v)
	{
		shuffle(v.begin(), v.end());
	}

	/// Chooses k random elements from the population without replacement.
	/// \param[out] collectedBegin  An iterator to the collected results.
	/// \param[in]  populationBegin An iterator to the start of the population.
	/// \param[in]  populationEnd   An iterator to the end of the population.
	/// \param[in]  k               The number of elements to choose.
	/// \param[in]  weightsBegin    An iterator to the start of the weights.
	/// \param[in]  weightsEnd      An iterator to the end of the weights.
	/// \returns The number of elements choosen.
	template <class CollectedIterator, class PopulationIterator, class WeightsIterator>
	size_t sample(CollectedIterator collectedBegin,
				  PopulationIterator populationBegin,
				  PopulationIterator populationEnd,
				  size_t k,
				  WeightsIterator weightsBegin,
				  WeightsIterator weightsEnd)
	{
		if (populationEnd <= populationBegin)
			return 0;
		size_t n = populationEnd - populationBegin, i, j;
		bool weighted = weightsBegin <= weightsEnd;
		double weightsSum = 0, r;
		if (weighted) {
			n = _min<size_t>(n, weightsEnd - weightsBegin);
			for (i = 0; i < n; ++i) {
				weightsSum += *(weightsBegin + i);
			}
			weighted = weightsSum > 0;
		}
		if (!weighted) {
			n = populationEnd - populationBegin;
			weightsSum = n;
		}
		
		size_t nSize = _max<size_t>(sizeof(uint8_t) * n, 1), ci = 0;
		uint8_t *visited = (uint8_t *) malloc(nSize);
		memset(visited, 0, nSize);

		for (j = 0; j < k; ++j) {
			r = weightsSum * random();
			for (i = 0; i < n; ++i) if (!visited[i]) {
				r -= weighted ? *(weightsBegin + i) : 1;
				if (r < 0) {
					*(collectedBegin + ci++) = *(populationBegin + i);
					weightsSum -= weighted ? *(weightsBegin + i) : 1;
					visited[i] = 1;
					i = n;
				}
			}
		}
		if (ci < k) for (i = 0; i < n; ++i) if (!visited[i])
			*(collectedBegin + ci++) = *(populationBegin + i);
		
		free(visited);

		shuffle(collectedBegin, collectedBegin + ci);
		return ci;
	}
	
	/// Chooses k random elements from the population without replacement.
	/// \param[out] collectedBegin  An iterator to the collected results.
	/// \param[in]  populationBegin An iterator to the start of the population.
	/// \param[in]  populationEnd   An iterator to the end of the population.
	/// \param[in]  k               The number of elements to choose.
	/// \returns The number of elements choosen.
	template <class CollectedIterator, class PopulationIterator>
	size_t sample(CollectedIterator collectedBegin,
				  PopulationIterator populationBegin,
				  PopulationIterator populationEnd,
				  size_t k=1)
	{
		return sample(collectedBegin,
					  populationBegin, populationEnd, k, _.buf+1, _.buf);
	}

	/// Chooses k random elements from the population without replacement.
	/// \param[out] collected       A vector/array-like container of elements.
	/// \param[in]  population      A vector/array-like container of elements.
	/// \param[in]  k               The number of elements to choose.
	/// \param[in]  weights         A vector/array-like container of weights.
	/// \returns The number of elements choosen.
	template <class Collected, class Population, class Weights>
	size_t sample(Collected &collected,
				  const Population &population,
				  size_t k,
				  const Weights &weights)
	{
		collected.resize(k);
		k = sample(collected.begin(), population.begin(), population.end(), k,
				   weights.begin(), weights.end());
		collected.resize(k);
		return k;
	}

	/// Chooses k random elements from the population without replacement.
	/// \param[out] collected       A vector/array-like container of elements.
	/// \param[in]  population      A vector/array-like container of elements.
	/// \param[in]  k               The number of elements to choose.
	/// \returns The number of elements choosen.
	template <class Collected, class Population>
	size_t sample(Collected &collected, const Population &population, size_t k=1)
	{
		collected.resize(k);
		k = sample(collected.begin(), population.begin(), population.end(), k);
		collected.resize(k);
		return k;
	}

	/// Chooses a random element from the population.
	/// \param[out] choicePointer   A pointer to the choosen element.
	/// \param[in]  populationBegin An iterator to the start of the population.
	/// \param[in]  populationEnd   An iterator to the end of the population.
	/// \param[in]  weightsBegin    An iterator to the start of the weights.
	/// \param[in]  weightsEnd      An iterator to the end of the weights.
	/// \returns Whether a choice is choosen.
	template <class ChoicePointer, class PopulationIterator, class WeightsIterator>
	bool choose(ChoicePointer choicePointer,
				PopulationIterator populationBegin,
				PopulationIterator populationEnd,
				WeightsIterator weightsBegin,
				WeightsIterator weightsEnd)
	{
		return sample(choicePointer, populationBegin, populationEnd, 1,
					  weightsBegin, weightsEnd);
	}
	
	/// Chooses a random element from the population.
	/// \param[out] choice     The choosen element.
	/// \param[in]  population A vector/array-like container of elements.
	/// \param[in]  weights    A vector/array-like container of weights.
	/// \returns Whether a choice is choosen.
	template <class Choice, class Population, class Weights>
	bool choose(Choice &choice,
				const Population &population,
				const Weights &weights)
	{
		return sample(&choice, population.begin(), population.end(), 1,
					  weights.begin(), weights.end());
	}
	
	/// Chooses a random element from the population.
	/// \param[out] choice     The choosen element.
	/// \param[in]  population A vector/array-like container of elements.
	/// \returns Whether a choice is choosen.
	template <class Choice, class Population>
	bool choose(Choice &choice, const Population &population)
	{
		return sample(&choice, population.begin(), population.end(), 1);
	}
	
	/// Returns a random number from the Gaussian distribution.
	/// \param[in] mu    The mean.
	/// \param[in] sigma The standard deviation.
	/// \returns A random number from the Gaussian distribution.
	double gauss(double mu=0, double sigma=1)
	{
		if (_.gaussHasSpare) {
			_.gaussHasSpare = 0;
			return _.gaussSpare * sigma + mu;
		}
		double s, u, v;
		while (1) {
			u = 2.0 * random() - 1.0;
			v = 2.0 * random() - 1.0;
			s = u * u + v * v;
			if (!(s >= 1.0 || s == 0.0))
				break;
		}
		s = sqrt(-2.0 * log(s) / s);
		_.gaussHasSpare = 1;
		_.gaussSpare = v * s;
		return u * s * sigma + mu;
	}
};

DEF_CHAINRAND_NAMESPACE_END

#undef DEF_CHAINRAND_NAMESPACE_BEGIN
#undef DEF_CHAINRAND_NAMESPACE_END
#endif