// CAST-128.cpp : Defines the entry point for the console application.
#include "CAST-128.h"
#include "cast_s.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <vector>
#include <cmath>
#include <random>
#include <iterator>
#include <iostream>
#include <functional>
// CAST-128.cpp : Defines the entry point for the console application.
#define _CRT_SECURE_NO_WARNINGS

UINT32 S[9][256];

// ============================================================================
// ==============================================================================

void InitSubstitutionBoxes(void)
{
	memcpy(S[1], CAST_S_table0, sizeof(CAST_S_table0));
	memcpy(S[2], CAST_S_table1, sizeof(CAST_S_table1));
	memcpy(S[3], CAST_S_table2, sizeof(CAST_S_table2));
	memcpy(S[4], CAST_S_table3, sizeof(CAST_S_table3));
	memcpy(S[5], CAST_S_table4, sizeof(CAST_S_table4));
	memcpy(S[6], CAST_S_table5, sizeof(CAST_S_table5));
	memcpy(S[7], CAST_S_table6, sizeof(CAST_S_table6));
	memcpy(S[8], CAST_S_table7, sizeof(CAST_S_table7));
}

// ============================================================================
// ==============================================================================
UINT32 fourByte2uint32(BYTE byte0, BYTE byte1, BYTE byte2, BYTE byte3)
{
	//~~~~~~~~~~~~~~~~~~
	UINT32 u32ret = byte0;
	//~~~~~~~~~~~~~~~~~~

	u32ret <<= 8;
	u32ret |= byte1;
	u32ret <<= 8;
	u32ret |= byte2;
	u32ret <<= 8;
	u32ret |= byte3;
	return u32ret;
};

// ============================================================================
// ==============================================================================

UINT32 byteArr2uint(const BYTE byte[16], int iByte)
{
	assert(iByte <= 12);
	return fourByte2uint32(byte[iByte], byte[iByte + 1], byte[iByte + 2], byte[iByte + 3]);
}

// ============================================================================
// ==============================================================================
void uint2fourByte(UINT32 uint, OUT BYTE &byte1, OUT BYTE &byte2, OUT BYTE &byte3, OUT BYTE &byte4)
{
	byte1 = (uint & 0xff000000) >> 24;
	byte2 = (uint & 0x00ff0000) >> 16;
	byte3 = (uint & 0x0000ff00) >> 8;
	byte4 = uint & 0x000000ff;
}

// ============================================================================
// ==============================================================================
void uint2fourByte(UINT32 uint, OUT BYTE byte[16], int iByte)
{
	assert(iByte <= 12);
	byte[iByte] = (uint & 0xff000000) >> 24;
	byte[iByte + 1] = (uint & 0x00ff0000) >> 16;
	byte[iByte + 2] = (uint & 0x0000ff00) >> 8;
	byte[iByte + 3] = uint & 0x000000ff;
}

// ============================================================================
// ==============================================================================
void byte82uint32LR(BYTE byte[8], UINT32 &L, UINT32 &R)
{
	L = byteArr2uint(byte, 0);
	R = byteArr2uint(byte, 4);

	// L = *(UINT32 *) (byte + 4);
	// R = *(UINT32 *) (byte);
}

// ============================================================================
// ==============================================================================
void uint32LR2byte8(OUT BYTE byte[8], UINT32 L, UINT32 R)
{
	uint2fourByte(L, byte, 0);
	uint2fourByte(R, byte, 4);

	// memcpy(byte, &L, 4);
	// memcpy(byte, &R, 4);
}

// ============================================================================
//    zx[izx]zx[izx+1]zx[izx+2]zx[izx+3] = xz[ixz]xz[ixz+1]xz[ixz+2]xz[ixz+3] ^
//    S5[iS5] ^ S6[iS6] ^S7 [iS7] ^ S8[iS8] ^ SiS[iSi];
// ============================================================================
void CaluZX(OUT BYTE zx[16],
			int izx,
			IN const BYTE xz[16],
			int ixz,
			int iS5,
			int iS6,
			int iS7,
			int iS8,
			int iS,
			int iSi)
{
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	UINT32 xz4byte = byteArr2uint(xz, ixz);
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	//printf("index %d-%d xz4byte = %x\n", ixz, ixz + 4, xz4byte);

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	UINT32 zx4byte = xz4byte ^ S[5][iS5] ^ S[6][iS6] ^ S[7][iS7] ^ S[8][iS8] ^ S[iS][iSi];
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	//printf("zx4byte(openssl-l) %x =  %x^%x^%x^%x^%x^%x\n", zx4byte, xz4byte, S[5][iS5], S[6][iS6], S[7][iS7], S[8][iS8],
		   //S[iS][iSi]);

	uint2fourByte(zx4byte, zx, izx);
}

// ============================================================================
//    K = S5[izx5] ^ S6[izx6] ^ S7[izx7] ^ S8[izx8] ^ Si[izxi];
// ============================================================================
UINT32 CaluK(IN const BYTE zx[16], int izxS5, int izxS6, int izxS7, int izxS8, int iS, int izxsSi)
{
	return S[5][zx[izxS5]] ^ S[6][zx[izxS6]] ^ S[7][zx[izxS7]] ^ S[8][zx[izxS8]] ^ S[iS][zx[izxsSi]];
}

// ============================================================================
// ==============================================================================
void CaluK(IN const BYTE key[16], OUT UINT32 Km[16], OUT UINT32 Kr[16])
{
	//~~~~~~~~~
	BYTE z[16];
	BYTE x[16];
	UINT32 k[33];
	//~~~~~~~~~

	// The subkeys are formed from the key x0x1x2x3x4x5x6x7x8x9xAxBxCxDxExF
	// as follows.
	memcpy(x, key, 16);

	//~~~~~~~~~~~~~~
	UINT32 *K = &k[0];
	//~~~~~~~~~~~~~~

CALCU_K16:
	// z0z1z2z3 = x0x1x2x3 ^ S5[xD] ^ S6[xF] ^ S7[xC] ^ S8[xE] ^ S7[x8];
	// z4z5z6z7 = x8x9xAxB ^ S5[z0] ^ S6[z2] ^ S7[z1] ^ S8[z3] ^ S8[xA];
	// z8z9zAzB = xCxDxExF ^ S5[z7] ^ S6[z6] ^ S7[z5] ^ S8[z4] ^ S5[x9];
	// zCzDzEzF = x4x5x6x7 ^ S5[zA] ^ S6[z9] ^ S7[zB] ^ S8[z8] ^ S6[xB];
	CaluZX(z, 0, x, 0, x[0xD], x[0xF], x[0xC], x[0xE], 7, x[0x8]);
	CaluZX(z, 4, x, 8, z[0], z[2], z[1], z[3], 8, x[0xA]);
	CaluZX(z, 8, x, 0xC, z[7], z[6], z[5], z[4], 5, x[9]);
	CaluZX(z, 0xC, x, 4, z[0xA], z[9], z[0xB], z[8], 6, x[0xB]);

	//for (int i = 0; i < 16; ++i) {
	//	printf("z %d %x\n", i, z[i]);
	//}

	// K1 = S5[z8] ^ S6[z9] ^ S7[z7] ^ S8[z6] ^ S5[z2];
	// K2 = S5[zA] ^ S6[zB] ^ S7[z5] ^ S8[z4] ^ S6[z6];
	// K3 = S5[zC] ^ S6[zD] ^ S7[z3] ^ S8[z2] ^ S7[z9];
	// K4 = S5[zE] ^ S6[zF] ^ S7[z1] ^ S8[z0] ^ S8[zC];
	K[1] = CaluK(z, 8, 9, 7, 6, 5, 2);
	K[2] = CaluK(z, 0xA, 0xB, 5, 4, 6, 6);
	K[3] = CaluK(z, 0xC, 0xD, 3, 2, 7, 9);
	K[4] = CaluK(z, 0xE, 0xF, 1, 0, 8, 0xC);

	// x0x1x2x3 = z8z9zAzB ^ S5[z5] ^ S6[z7] ^ S7[z4] ^ S8[z6] ^ S7[z0];
	// x4x5x6x7 = z0z1z2z3 ^ S5[x0] ^ S6[x2] ^ S7[x1] ^ S8[x3] ^ S8[z2];
	// x8x9xAxB = z4z5z6z7 ^ S5[x7] ^ S6[x6] ^ S7[x5] ^ S8[x4] ^ S5[z1];
	// xCxDxExF = zCzDzEzF ^ S5[xA] ^ S6[x9] ^ S7[xB] ^ S8[x8] ^ S6[z3];
	CaluZX(x, 0, z, 8, z[5], z[7], z[4], z[6], 7, z[0]);
	CaluZX(x, 4, z, 0, x[0], x[2], x[1], x[3], 8, z[2]);
	CaluZX(x, 8, z, 4, x[7], x[6], x[5], x[4], 5, z[1]);
	CaluZX(x, 0xC, z, 0xC, x[0xA], x[9], x[0xB], x[8], 6, z[3]);

	// K5 = S5[x3] ^ S6[x2] ^ S7[xC] ^ S8[xD] ^ S5[x8];
	// K6 = S5[x1] ^ S6[x0] ^ S7[xE] ^ S8[xF] ^ S6[xD];
	// K7 = S5[x7] ^ S6[x6] ^ S7[x8] ^ S8[x9] ^ S7[x3];
	// K8 = S5[x5] ^ S6[x4] ^ S7[xA] ^ S8[xB] ^ S8[x7];
	K[5] = CaluK(x, 3, 2, 0xC, 0xD, 5, 8);
	K[6] = CaluK(x, 1, 0, 0xE, 0xF, 6, 0xD);
	K[7] = CaluK(x, 7, 6, 8, 9, 7, 3);
	K[8] = CaluK(x, 5, 4, 0xA, 0xB, 8, 7);

	// z0z1z2z3 = x0x1x2x3 ^ S5[xD] ^ S6[xF] ^ S7[xC] ^ S8[xE] ^ S7[x8];
	// z4z5z6z7 = x8x9xAxB ^ S5[z0] ^ S6[z2] ^ S7[z1] ^ S8[z3] ^ S8[xA];
	// z8z9zAzB = xCxDxExF ^ S5[z7] ^ S6[z6] ^ S7[z5] ^ S8[z4] ^ S5[x9];
	// zCzDzEzF = x4x5x6x7 ^ S5[zA] ^ S6[z9] ^ S7[zB] ^ S8[z8] ^ S6[xB];
	CaluZX(z, 0, x, 0, x[0xD], x[0xF], x[0xC], x[0xE], 7, x[8]);
	CaluZX(z, 4, x, 8, z[0], z[2], z[1], z[3], 8, x[0xA]);
	CaluZX(z, 8, x, 0xC, z[7], z[6], z[5], z[4], 5, x[9]);
	CaluZX(z, 0xC, x, 4, z[0xA], z[9], z[0xB], z[8], 6, x[0xB]);

	// K9 = S5[z3] ^ S6[z2] ^ S7[zC] ^ S8[zD] ^ S5[z9];
	// K10 = S5[z1] ^ S6[z0] ^ S7[zE] ^ S8[zF] ^ S6[zC];
	// K11 = S5[z7] ^ S6[z6] ^ S7[z8] ^ S8[z9] ^ S7[z2];
	// K12 = S5[z5] ^ S6[z4] ^ S7[zA] ^ S8[zB] ^ S8[z6];
	K[9] = CaluK(z, 3, 2, 0xC, 0xD, 5, 9);
	K[10] = CaluK(z, 1, 0, 0xE, 0xF, 6, 0xC);
	K[11] = CaluK(z, 7, 6, 8, 9, 7, 2);
	K[12] = CaluK(z, 5, 4, 0xA, 0xB, 8, 6);

	// x0x1x2x3 = z8z9zAzB ^ S5[z5] ^ S6[z7] ^ S7[z4] ^ S8[z6] ^ S7[z0];
	// x4x5x6x7 = z0z1z2z3 ^ S5[x0] ^ S6[x2] ^ S7[x1] ^ S8[x3] ^ S8[z2];
	// x8x9xAxB = z4z5z6z7 ^ S5[x7] ^ S6[x6] ^ S7[x5] ^ S8[x4] ^ S5[z1];
	// xCxDxExF = zCzDzEzF ^ S5[xA] ^ S6[x9] ^ S7[xB] ^ S8[x8] ^ S6[z3];
	CaluZX(x, 0, z, 8, z[5], z[7], z[4], z[6], 7, z[0]);
	CaluZX(x, 4, z, 0, x[0], x[2], x[1], x[3], 8, z[2]);
	CaluZX(x, 8, z, 4, x[7], x[6], x[5], x[4], 5, z[1]);
	CaluZX(x, 0xC, z, 0xC, x[0xA], x[9], x[0xB], x[8], 6, z[3]);

	// K13 = S5[x8] ^ S6[x9] ^ S7[x7] ^ S8[x6] ^ S5[x3];
	// K14 = S5[xA] ^ S6[xB] ^ S7[x5] ^ S8[x4] ^ S6[x7];
	// K15 = S5[xC] ^ S6[xD] ^ S7[x3] ^ S8[x2] ^ S7[x8];
	// K16 = S5[xE] ^ S6[xF] ^ S7[x1] ^ S8[x0] ^ S8[xD];
	K[13] = CaluK(x, 8, 9, 7, 6, 5, 3);
	K[14] = CaluK(x, 0xA, 0xB, 5, 4, 6, 7);
	K[15] = CaluK(x, 0xC, 0xD, 3, 2, 7, 8);
	K[16] = CaluK(x, 0xE, 0xF, 1, 0, 8, 0xD);

	//for (int i = 1; i <= 16; ++i) {
	//	printf("K %d : %x\n", K - k + i, K[i]);
	//}

	if (K == k) {
		K += 16;
		goto CALCU_K16;
	}

	// Let Km1, ..., Km16 be 32-bit masking subkeys (one per round). Let
	// Kr1, , Kr16 be 32-bit rotate subkeys (one per round);
	// only the least significant 5 bits are used in each round.;
	// for (i=1;
	// i<=16;
	// i++) { Kmi = Ki;
	// Kri = K16+i;
	// };
	for (int i = 1; i <= 16; ++i) {
		Km[i] = k[i];
		Kr[i] = k[16 + i] & 0x1f;
	}

	//for (int i = 1; i <= 16; ++i) {
	//	printf("i %d  Kmi %x, Kri %x\n", i, Km[i], Kr[i]);
	//}
}

// ============================================================================
// ==============================================================================
UINT32 uint32cirShiftL(UINT32 uint32, int nLeftShift)
{
	return(uint32 >> (32 - nLeftShift)) | (uint32 << nLeftShift);
}

// ============================================================================
// ==============================================================================
UINT32 uint32cirShiftR(UINT32 uint32, int nRightShift)
{
	return(uint32 << (32 - nRightShift)) | (uint32 >> nRightShift);
}

UINT32 roundFunction(int iRound, UINT32 D)
{
	//~~~~~~~~~~~~~~~~
	UINT32 u32f;
	BYTE Ia, Ib, Ic, Id;
	//~~~~~~~~~~~~~~~~

	switch (iRound % 3) {
	case 1:
		uint2fourByte(D, Ia, Ib, Ic, Id);

		// f = ((S1[Ia] ^ S2[Ib]) - S3[Ic]) + S4[Id];
		u32f = (S[1][Ia] ^ S[2][Ib]) - S[3][Ic] + S[4][Id];
		break;
	case 2:
		uint2fourByte(D, Ia, Ib, Ic, Id);

		// f = ((S1[Ia] - S2[Ib]) + S3[Ic]) ^ S4[Id];
		u32f = ((S[1][Ia] - S[2][Ib]) + S[3][Ic]) ^ S[4][Id];
		break;
	case 0:
		uint2fourByte(D, Ia, Ib, Ic, Id);

		// f = ((S1[Ia] + S2[Ib]) ^ S3[Ic]) - S4[Id];
		u32f = ((S[1][Ia] + S[2][Ib]) ^ S[3][Ic]) - S[4][Id];
		break;
	default:
		assert(0);
		break;
	}

	return u32f;
}



// ============================================================================
//    Three different round functions are used in CAST-128. The rounds are as
//    follows (where "D" is the data input to the f function and "Ia" - "Id" are
//    the most significant byte through least significant byte of I,
//    respectively). Note that "+" and "-" are addition and subtraction modulo
//    2**32, "^" is bitwise XOR, and "<<<" is the circular left- shift
//    operation.;
//    Rounds 1, 4, 7, 10, 13, and 16 use f function Type 1;
//    Rounds 2, 5, 8, 11, and 14 use f function Type 2;
//    Rounds 3, 6, 9, 12, and 15 use f function Type 3;
// ============================================================================
UINT32 f(int iRound, int D, UINT32 Kmi, UINT32 Kri)
{
	//~~~~~~~~~~~~~~~~
	UINT32 I;
	UINT32 u32f;
	BYTE Ia, Ib, Ic, Id;
	//~~~~~~~~~~~~~~~~

	switch (iRound % 3) {
	case 1:
		// Type 1: I = ((Kmi + D) <<< Kri);
		I = uint32cirShiftL(Kmi + D, Kri);
		uint2fourByte(I, Ia, Ib, Ic, Id);

		// f = ((S1[Ia] ^ S2[Ib]) - S3[Ic]) + S4[Id];
		u32f = (S[1][Ia] ^ S[2][Ib]) - S[3][Ic] + S[4][Id];
		break;
	case 2:
		// Type 2: I = ((Kmi ^ D) <<< Kri);
		I = uint32cirShiftL(Kmi ^ D, Kri);
		uint2fourByte(I, Ia, Ib, Ic, Id);

		// f = ((S1[Ia] - S2[Ib]) + S3[Ic]) ^ S4[Id];
		u32f = ((S[1][Ia] - S[2][Ib]) + S[3][Ic]) ^ S[4][Id];
		break;
	case 0:
		// Type 3: I = ((Kmi - D) <<< Kri);
		I = uint32cirShiftL(Kmi - D, Kri);
		uint2fourByte(I, Ia, Ib, Ic, Id);

		// f = ((S1[Ia] + S2[Ib]) ^ S3[Ic]) - S4[Id];
		u32f = ((S[1][Ia] + S[2][Ib]) ^ S[3][Ic]) - S[4][Id];
		break;
	default:
		assert(0);
		break;
	}

	return u32f;
}

// ============================================================================
// ==============================================================================
void enc(int ROUND,BYTE plaintext, BYTE* ciphertext)
{
	
        InitSubstitutionBoxes();

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	
	UINT32 L[ROUND + 1];
	UINT32 R[ROUND + 1];
	

	BYTE key[16] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };
	// 1. (key schedule) Compute 16 pairs of subkeys {Kmi, Kri} from K;
	UINT32 Km[16];
	UINT32 Kr[16];
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	CaluK(key, Km, Kr);
        
       
        //srand(time(NULL));
        //for (int i = 0; i < 8; i++) {
         //  plaintext[i] = rand() % 256;
        //}
    
        
	byte82uint32LR(plaintext, L[0], R[0]);
        
       

        //R[0]=(UINT32)data;
	for (int i = 1; i <= ROUND; ++i) {
		L[i] = R[i - 1];
		R[i] = L[i - 1] ^ f(i, R[i - 1], Km[i], Kr[i]);
	}

	//~~~~~~~~~~~~~~~
	// 4. c1...c64 <-- (R16,L16). (Exchange final blocks L16, R16 and
	// concatenate to form the ciphertext.
        
	//~~~~~~~~~~~~~~~

	uint32LR2byte8(ciphertext, R[3], L[3]);
        
        //for (int i = 0; i <= 8; ++i) {
	//	c[i] = ciphertext[i];
		
	//}

//for (int i = 0; i < 8; ++i) {
//	printf("%x ", plaintext[i]);
//}
 // for (int i = 0; i < 8; ++i) {
//	printf("%x ", c[i]);
//}

}
//int main(){

//std::vector<double> T(1L << 16, 0);



    //static std::mt19937 rng{ std::random_device{}() };
    //std::uniform_real_distribution<double> dist(0, 4);
    //dist(rng);
    //std::cout << rng << std::endl;

//return 0;
//}

template< class Iter >
void fill_with_random_int_values( Iter start, Iter end, int min, int max)
{
    static std::random_device rd;    // you only need to initialize it once
    static std::mt19937 mte(rd());   // this is a relative big object to create

    std::uniform_int_distribution<BYTE> dist(min, max);

    std::generate(start, end, [&] () { return dist(mte); });
}

int main()
{   
    int ROUND=3;
    std::array<BYTE, 8> plaintext;
    std::array<BYTE, 8> ciphertext;
    for (int j = 0; j < pow(2,16); ++j) {
    fill_with_random_int_values(plaintext.begin(), plaintext.end(), 0, 255);

    for ( int i : plaintext ) std::cout << std::hex << i << ' ';
    std::cout << '\n';

    UINT32 L[ROUND + 1];
    UINT32 R[ROUND + 1];
	

	BYTE key[16] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };
	// 1. (key schedule) Compute 16 pairs of subkeys {Kmi, Kri} from K;
	UINT32 Km[16];
	UINT32 Kr[16];
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	CaluK(key, Km, Kr);
        
       
        //srand(time(NULL));
        //for (int i = 0; i < 8; i++) {
         //  plaintext[i] = rand() % 256;
        //}
    
        
	byte82uint32LR(plaintext, L[0], R[0]);
        
       

        //R[0]=(UINT32)data;
	for (int i = 1; i <= ROUND; ++i) {
		L[i] = R[i - 1];
		R[i] = L[i - 1] ^ f(i, R[i - 1], Km[i], Kr[i]);
	}

	//~~~~~~~~~~~~~~~
	// 4. c1...c64 <-- (R16,L16). (Exchange final blocks L16, R16 and
	// concatenate to form the ciphertext.
        
	//~~~~~~~~~~~~~~~

	uint32LR2byte8(ciphertext, R[3], L[3]);
    for ( int i : ciphertext ) std::cout << std::hex << i << ' ';
    std::cout << '\n';
    
    }
}

int mainf()
{
	InitSubstitutionBoxes();

	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	const int ROUND = 3;
	UINT32 L[ROUND + 1];
	UINT32 R[ROUND + 1];
	// INPUT: plaintext m1...m64;ebc9bf60
	// key K = k1...k128.;
	BYTE plaintext[8];
	BYTE key[16] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };
	// 1. (key schedule) Compute 16 pairs of subkeys {Kmi, Kri} from K;
	UINT32 Km[16];
	UINT32 Kr[16];
	//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	CaluK(key, Km, Kr);
        
       
        srand(time(NULL));
        for (int i = 0; i < 8; i++) {
            plaintext[i] = rand() % 256;
        }
    
	// 2. (L0,R0) <-- (m1...m64). (Split the plaintext into left and right
	// 32-bit halves L0 = m1...m32 and R0 = m33...m64.);
	byte82uint32LR(plaintext, L[0], R[0]);
        //L[0]={0};
        //std::random_device rd;
        //std::uniform_int_distribution<UINT32> dist(0,pow(2,32)-1);
     
        //R[0] = dist(rd);
       
         //std::cout << std::hex << L[0] << std::endl;
         //std::cout << std::hex << R[0] << std::endl;
         //std::cout << "\n"<<std::endl;

        //R[0]=(UINT32)data;
	// 3. (16 rounds) for i from 1 to 16, compute Li and Ri as follows:;
	// Li = Ri-1;
	// Ri = Li-1 ^ f(Ri-1,Kmi,Kri), where f is defined in Section 2.2;
	// (f is of Type 1, Type 2, or Type 3, depending on i).;
	for (int i = 1; i <= ROUND; ++i) {
		L[i] = R[i - 1];
		R[i] = L[i - 1] ^ f(i, R[i - 1], Km[i], Kr[i]);
	}

	//~~~~~~~~~~~~~~~
	// 4. c1...c64 <-- (R16,L16). (Exchange final blocks L16, R16 and
	// concatenate to form the ciphertext.
	BYTE ciphertext[8];
	//~~~~~~~~~~~~~~~

	uint32LR2byte8(ciphertext, R[3], L[3]);

	//printf("ciphertext: ");
	//for (int i = 0; i < 8; ++i) {
	//	printf("%x ", ciphertext[i]);
	//}

	//printf("\n");

	// Decryption is identical to the encryption algorithm given above,;
	// except that the rounds (and therefore the subkey pairs) are used in;
	// reverse order to compute (L0,R0) from (R16,L16).;
	//for (int i = ROUND - 1; i >= 0; --i) {

		// Ri = Li+1;
		// Li = Ri+1 ^ f(Ri, Kmi+1, Kri+1);
	//	R[i] = L[i + 1];
	//	L[i] = R[i + 1] ^ f(i + 1, R[i], Km[i + 1], Kr[i + 1]);
	//}

	//~~~~~~~~~~~~
	BYTE orgText[8];
	//~~~~~~~~~~~~

	uint32LR2byte8(orgText, L[0], R[0]);

	//printf("orgText: ");
	//for (int i = 0; i < 8; ++i) {
	//	printf("%x ", orgText[i]);
	//}

	//printf("\n");

	//~~~~~~~~~~~~~
	//char szLine[256];
	//~~~~~~~~~~~~~

	//while (gets_s(szLine, sizeof(szLine)));

	return 0;
}

