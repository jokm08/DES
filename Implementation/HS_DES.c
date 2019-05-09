/********************************************************************/
/*                                                                  */
/*                DES - Data Encryption Standard                    */
/*                                                                  */
/* Date        : 2/10/2019                                          */
/* Author(s)   : Jose Kurian Manooparambil, Tenzing Rabgyal         */
/* Course      : Introduction to Hardware Security and Trust        */
/* Institution : Tandon School of Engineering, New York University  */
/*                                                                  */
/********************************************************************/

#include<stdio.h>
#include"HS_DES.h"

/*Type def*/
typedef char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

/*Constant One*/

uint32_t one32_bit = 1;
uint64_t one64_bit = 1;

/*Defining the bit positions to generate initial permutation*/

#define bitpos_00  (1)
#define bitpos_01  (2)
#define bitpos_02  (4)
#define bitpos_03  (8)
#define bitpos_04  (16)
#define bitpos_05  (32)
#define bitpos_06  (64)
#define bitpos_07  (128)
#define bitpos_08  (256)
#define bitpos_09  (512)
#define bitpos_10  (1024)
#define bitpos_11  (2048)
#define bitpos_12  (4096)
#define bitpos_13  (8192)
#define bitpos_14  (16384)
#define bitpos_15  (32768)
#define bitpos_16  (65536)
#define bitpos_17  (131072)
#define bitpos_18  (262144)
#define bitpos_19  (524288)
#define bitpos_20  (1048576)
#define bitpos_21  (2097152)
#define bitpos_22  (4194304)
#define bitpos_23  (8388608)
#define bitpos_24  (16777216)
#define bitpos_25  (33554432)
#define bitpos_26  (67108864)
#define bitpos_27  (134217728)
#define bitpos_28  (268435456)
#define bitpos_29  (536870912)
#define bitpos_30  (1073741824)
#define bitpos_31  (2147483648)
#define bitpos_32  (4294967296)
#define bitpos_33  (8589934592)
#define bitpos_34  (17179869184)
#define bitpos_35  (34359738368)
#define bitpos_36  (68719476736)
#define bitpos_37  (137438953472)
#define bitpos_38  (274877906944)
#define bitpos_39  (549755813888)
#define bitpos_40  (1099511627776)
#define bitpos_41  (2199023255552)
#define bitpos_42  (4398046511104)
#define bitpos_43  (8796093022208)
#define bitpos_44  (17592186044416)
#define bitpos_45  (35184372088832)
#define bitpos_46  (70368744177664)
#define bitpos_47  (140737488355328)
#define bitpos_48  (281474976710656)
#define bitpos_49  (562949953421312)
#define bitpos_50  (1125899906842624)
#define bitpos_51  (2251799813685248)
#define bitpos_52  (4503599627370496)
#define bitpos_53  (9007199254740992)
#define bitpos_54  (18014398509481984)
#define bitpos_55  (36028797018963968)
#define bitpos_56  (72057594037927936)
#define bitpos_57  (144115188075855872)
#define bitpos_58  (288230376151711744)
#define bitpos_59  (576460752303423488)
#define bitpos_60  (1152921504606846976)
#define bitpos_61  (2305843009213693952)
#define bitpos_62  (4611686018427387904)
#define bitpos_63  (9223372036854775808)

/*Initial permutation for left side*/

/* Input        : 07 15 23 31 39 47 55 63 05 13 21 29 37 45 53 61 03 11 19 27 35 43 51 59 01 09 17 25 33 41 49 57 */
/* Bit Position : 31 30 ....................................................................................01 00 */ 

uint32_t initial_permutation_left_32bit(uint64_t input_block_64bit)
{
	uint16_t i;
	uint32_t IP_Left = 0;
	
	uint16_t IP_Left_Pos[32] = {58,50,42,34,26,18,10,2,\
							   	60,52,44,36,28,20,12,4,\
							   	62,54,46,38,30,22,14,6,\
					   			64,56,48,40,32,24,16,8};
					   
	for(i=0;i<32;i++)
	{
		if((31 - i - (64-IP_Left_Pos[i])) > 0)
		{
			IP_Left = (uint32_t)((input_block_64bit & ((uint64_t)(1) << (64 - IP_Left_Pos[i]))) << (31 - i - (64 - IP_Left_Pos[i]))) | IP_Left;	
		}
		else
		{
			IP_Left = (uint32_t)((input_block_64bit & ((uint64_t)(1) << (64 - IP_Left_Pos[i]))) >> (64 - IP_Left_Pos[i] - (31 - i))) | IP_Left;	
		}
	}					   
	
	/*IP_Left = uint32_t((input_block_64bit & bitpos_57) >> 57) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_49) >> 48) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_41) >> 39) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_33) >> 30) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_25) >> 21) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_17) >> 12) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_09) >> 3)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_01) << 6)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_59) >> 51) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_51) >> 42) | IP_Left;	
	IP_Left = uint32_t((input_block_64bit & bitpos_43) >> 33) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_35) >> 24) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_27) >> 15) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_19) >> 6)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_11) << 3)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_03) << 12) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_61) >> 45) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_53) >> 36) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_45) >> 27) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_37) >> 18) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_29) >> 9)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_21) >> 0)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_13) << 9)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_05) << 18) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_63) >> 39) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_55) >> 30) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_47) >> 21) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_39) >> 12) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_31) >> 3)  | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_23) << 6)  | IP_Left;		
	IP_Left = uint32_t((input_block_64bit & bitpos_15) << 15) | IP_Left;
	IP_Left = uint32_t((input_block_64bit & bitpos_07) << 24) | IP_Left;*/
	
	return IP_Left;
}

/*Initial permutation for Right side*/

/* Input        : 06 14 22 30 38 46 54 62 04 12 20 28 36 44 52 60 02 10 18 26 34 42 50 58 00 08 16 24 32 40 48 56 */
/* Bit Position : 31 30 ....................................................................................01 00 */ 

uint32_t initial_permutation_right_32bit(uint64_t input_block_64bit)
{
	uint16_t i;
	uint32_t IP_Right = 0;
	
	uint16_t IP_Right_Pos[32] = {57,49,41,33,25,17,9,1,\
								 59,51,43,35,27,19,11,3,\
								 61,53,45,37,29,21,13,5,\
								 63,55,47,39,31,23,15,7};
					
	for(i=0;i<32;i++)
	{
		if((31 - i - (64-IP_Right_Pos[i])) > 0)
		{
			IP_Right = (uint32_t)((input_block_64bit & ((uint64_t)(1) << (64 - IP_Right_Pos[i]))) << (31 - i - (64 - IP_Right_Pos[i]))) | IP_Right;	
		}
		else
		{
			IP_Right = (uint32_t)((input_block_64bit & ((uint64_t)(1) << (64 - IP_Right_Pos[i]))) >> (64 - IP_Right_Pos[i] - (31 - i))) | IP_Right;	
		}
	}					   
					
	
	/*IP_Right = uint32_t((input_block_64bit & bitpos_56) >> 56) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_48) >> 47) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_40) >> 38) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_32) >> 29) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_24) >> 20) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_16) >> 11) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_08) >> 2)  | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_00) << 7)  | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_58) >> 50) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_50) >> 41) | IP_Right;	
	IP_Right = uint32_t((input_block_64bit & bitpos_42) >> 32) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_34) >> 23) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_26) >> 14) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_18) >> 5)  | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_10) << 4)  | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_02) << 13) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_60) >> 44) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_52) >> 35) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_44) >> 26) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_36) >> 17) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_28) >> 8)  | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_20) << 1)  | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_12) << 10) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_04) << 19) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_62) >> 38) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_54) >> 29) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_46) >> 20) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_38) >> 11) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_30) >> 2)  | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_22) << 7)  | IP_Right;		
	IP_Right = uint32_t((input_block_64bit & bitpos_14) << 16) | IP_Right;
	IP_Right = uint32_t((input_block_64bit & bitpos_06) << 25) | IP_Right;*/
	
	return IP_Right;
}

/*Expansion Block - E*/

uint64_t expansion_block(uint32_t right_block)
{
	uint16_t i;
	uint64_t blockExp = 0;
	
	uint16_t E[48] = {32,1,2,3,4,5,4,5,\
					  6,7,8,9,8,9,10,11,\
					  12,13,12,13,14,15,16,17,\
					  16,17,18,19,20,21,20,21,\
					  22,23,24,25,24,25,26,27,\
					  28,29,28,29,30,31,32,1};	
					  
	printf("Right Block = %X",right_block);
								 
	for(i=0;i<48;i++)
	{
		if((47 - i - (32 - E[i])) > 0)
		{
			blockExp = (uint64_t)((uint64_t)(right_block & ((uint32_t)(1) << (32 - E[i]))) << (47 - i - (32 - E[i]))) | blockExp;	
		}
		else
		{
			blockExp = (uint64_t)((uint64_t)(right_block & ((uint32_t)(1) << (32 - E[i]))) >> (32 - E[i] - (47 - i))) | blockExp;	
		}
	}
	
	printf("\nExpansion Block = %llX",blockExp);
	
	return blockExp;								 
	
	/*blockExp = uint64_t((right_block & bitpos_31) >> 31) | blockExp;

	blockExp = uint64_t((right_block & bitpos_00) << 1)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_01) << 1)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_02) << 1)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_03) << 1)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_04) << 1)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_05) << 1)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_04) << 3)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_05) << 3)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_06) << 3)  | blockExp;
    blockExp = uint64_t((right_block & bitpos_07) << 3)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_08) << 3)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_09) << 3)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_08) << 5)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_09) << 5)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_10) << 5)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_11) << 5)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_12) << 5)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_13) << 5)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_12) << 7)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_13) << 7)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_14) << 7)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_15) << 7)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_16) << 7)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_17) << 7)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_16) << 9)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_17) << 9)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_18) >> 9)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_19) << 9)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_20) << 9)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_21) << 9)  | blockExp;
	blockExp = uint64_t((right_block & bitpos_20) << 11) | blockExp;
	blockExp = uint64_t((right_block & bitpos_21) << 11) | blockExp;
	blockExp = uint64_t((right_block & bitpos_22) << 11) | blockExp;
	blockExp = uint64_t((right_block & bitpos_23) << 11) | blockExp;
	blockExp = uint64_t((right_block & bitpos_24) << 11) | blockExp;
	blockExp = uint64_t((right_block & bitpos_25) << 11) | blockExp;
	blockExp = uint64_t((right_block & bitpos_24) << 13) | blockExp;
	blockExp = uint64_t((right_block & bitpos_25) << 13) | blockExp;
	blockExp = uint64_t((right_block & bitpos_26) << 13) | blockExp;
	blockExp = uint64_t((right_block & bitpos_27) << 13) | blockExp;
	blockExp = uint64_t((right_block & bitpos_28) << 13) | blockExp;
	blockExp = uint64_t((right_block & bitpos_29) << 13) | blockExp;
	blockExp = uint64_t((right_block & bitpos_28) << 15) | blockExp;
	blockExp = uint64_t((right_block & bitpos_29) << 15) | blockExp;
	blockExp = uint64_t((right_block & bitpos_30) << 15) | blockExp;
	blockExp = uint64_t((right_block & bitpos_31) << 15) | blockExp;
	blockExp = uint64_t((right_block & bitpos_00) << 17) | blockExp;*/		
}

/*Substitution Functions - S*/

uint32_t substitution_function(uint64_t block)
{
	uint32_t permutation = 0, temp = 0;
	uint16_t i;
	uint16_t row1,row2,row3,row4,row5,row6,row7,row8;
	uint16_t col1,col2,col3,col4,col5,col6,col7,col8;
	uint32_t val1,val2,val3,val4,val5,val6,val7,val8;
	
	uint16_t S1[4][16] = {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
	                     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
						 {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
						 {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};
				
	uint16_t S2[4][16] = {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
	                     {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
						 {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
						 {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};
						
	uint16_t S3[4][16] = {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
	                     {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
						 {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
						 {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};
						 
	uint16_t S4[4][16] = {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
	                     {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
						 {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
						 {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};
						 
	uint16_t S5[4][16] = {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
	                     {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
						 {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
						 {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};
						 
	uint16_t S6[4][16] = {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
	                     {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
						 {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
						 {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}}; 
						 
	uint16_t S7[4][16] = {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
	                     {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
						 {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
						 {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}}; 
						 
	uint16_t S8[4][16] = {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
	                     {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
						 {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
						 {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
						 
	uint16_t P[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
	
	row8 = (uint16_t) ((block & bitpos_00) | ((block & bitpos_05) >> 4));
	col8 = (uint16_t) (((block & bitpos_01) >> 1) | ((block & bitpos_02) >> 1) | ((block & bitpos_03) >> 1) | ((block & bitpos_04) >> 1));

	val8 = S8[row8][col8];

	row7 = (uint16_t) (((block & bitpos_06) >> 6) | ((block & bitpos_11) >> 10));
	col7 = (uint16_t) (((block & bitpos_07) >> 7) | ((block & bitpos_08) >> 7) | ((block & bitpos_09) >> 7) | ((block & bitpos_10) >> 7));

	val7 = S7[row7][col7];

	row6 = (uint16_t) (((block & bitpos_12) >> 12) | ((block & bitpos_17) >> 16));
	col6 = (uint16_t) (((block & bitpos_13) >> 13) | ((block & bitpos_14) >> 13) | ((block & bitpos_15) >> 13) | ((block & bitpos_16) >> 13));
	
	val6 = S6[row6][col6];

	row5 = (uint16_t) (((block & bitpos_18) >> 18) | ((block & bitpos_23) >> 22));
	col5 = (uint16_t) (((block & bitpos_19) >> 19) | ((block & bitpos_20) >> 19) | ((block & bitpos_21) >> 19) | ((block & bitpos_22) >> 19));
	
	val5 = S5[row5][col5]; 
	
	row4 = (uint16_t) (((block & bitpos_24) >> 24) | ((block & bitpos_29) >> 28));
	col4 = (uint16_t) (((block & bitpos_25) >> 25) | ((block & bitpos_26) >> 25) | ((block & bitpos_27) >> 25) | ((block & bitpos_28) >> 25));
	
	val4 = S4[row4][col4];

	row3 = (uint16_t) (((block & bitpos_30) >> 30) | ((block & bitpos_35) >> 34));
	col3 = (uint16_t) (((block & bitpos_31) >> 31) | ((block & bitpos_32) >> 31) | ((block & bitpos_33) >> 31) | ((block & bitpos_34) >> 31));
	
	val3 = S3[row3][col3];	
	
	row2 = (uint16_t) (((block & bitpos_36) >> 36) | ((block & bitpos_41) >> 40));
	col2 = (uint16_t) (((block & bitpos_37) >> 37) | ((block & bitpos_38) >> 37) | ((block & bitpos_39) >> 37) | ((block & bitpos_40) >> 37));
	
	val2 = S2[row2][col2];

	row1 = (uint16_t) (((block & bitpos_42) >> 42) | ((block & bitpos_47) >> 46));
	col1 = (uint16_t) (((block & bitpos_43) >> 43) | ((block & bitpos_44) >> 43) | ((block & bitpos_45) >> 43) | ((block & bitpos_46) >> 43));
	
	val1 = S1[row1][col1];
	
	temp = (val1 << 28) | (val2 << 24) | (val3 << 20) | (val4 << 16) | (val5 << 12) | (val6 << 8) | (val7 << 4) | val8;	
	
	printf("\nSubstitution = %X",temp);
	
	
	for(i=0;i<32;i++)
	{
		if((31 - i - (32 - P[i])) > 0)
		{
			permutation = (uint32_t) ((temp & ((uint32_t)(1) << (32 - P[i]))) << (31 - i - (32 - P[i]))) | permutation;
		}
		else
		{
			permutation = (uint32_t) ((temp & ((uint32_t)(1) << (32 - P[i]))) >> (32 - P[i] - (31 - i))) | permutation;
		}			
	}
	
	
			
	return permutation;
	
}

uint32_t exclusive_Or(uint32_t left,uint32_t right_processed)
{
	return (left ^ right_processed);
}

uint64_t inverse_initial_permutation(uint32_t left, uint32_t right)
{
	uint16_t i;
	uint64_t temp = 0, inverse_permutation = 0;
	
	uint16_t IP_1[64] = {40,8,48,16,56,24,64,32,\
	                     39,7,47,15,55,23,63,31,\
						 38,6,46,14,54,22,62,30,\
						 37,5,45,13,53,21,61,29,\
						 36,4,44,12,52,20,60,28,\
						 35,3,43,11,51,19,59,27,\
						 34,2,42,10,50,18,58,26,\
						 33,1,41,9,49,17,57,25};
	
	temp = temp | (uint64_t)(left);
	
	temp = temp << 32;
	
	temp = temp | right;
	
	for(i=0;i<64;i++)
	{
		if((63 - i - (64 - IP_1[i])) > 0)
		{
			inverse_permutation = (uint64_t)((temp & ((uint64_t)(1) << (64 - IP_1[i]))) << (63 - i - (64 - IP_1[i]))) | inverse_permutation;
		}
		else
		{
			inverse_permutation = (uint64_t)((temp & ((uint64_t)(1) << (64 - IP_1[i]))) >> (64 - IP_1[i] - (63 - i))) | inverse_permutation;
		}
		
	}
	
	return inverse_permutation;
	 
};

uint32_t DES_F_Function(uint32_t Block_R, uint64_t Key)
{
	uint64_t E, S_Block_Input;
	
	E = expansion_block(Block_R);
	
	S_Block_Input = Key ^ E;
	
	printf("\nSubstitution input = %llX",S_Block_Input);
	
	return(substitution_function(S_Block_Input));

}
