/********************************************************************/
/*                                                                  */
/*             DES Key - Data Encryption Standard Key               */
/*                                                                  */
/* Date        : 2/12/2019                                          */
/* Author(s)   : Jose Kurian Manooparambil, Tenzing Rabgyal         */
/* Course      : Introduction to Hardware Security and Trust        */
/* Institution : Tandon School of Engineering, New York University  */
/*                                                                  */
/********************************************************************/

#include<stdio.h>
#include"HS_DESKey.h"

uint32_t initial_permuted_choice_left(uint64_t key)
{
	uint16_t i;
	uint32_t C = 0;
	
	uint16_t L[28] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36};

	for(i=0;i<28;i++)
	{
		if((27 - i - (64-L[i])) > 0)
		{
			C = (uint32_t)((key & ((uint64_t)(1) << (64 - L[i]))) << (27 - i - (64 - L[i]))) | C;	
		}
		else
		{
			C = (uint32_t)((key & ((uint64_t)(1) << (64 - L[i]))) >> (64 - L[i] - (27 - i))) | C;	
		}
	}
	/*for(i=27;i>=0;i--)
	{
		if((27-i-L[i]) > 0)
		{
			printf("\n%d",L[i]);
			C = (uint32_t)((key & ((uint64_t)(1) << L[i])) << (27 - i - L[i])) | C;
			printf(" %X",C);
		}
		else
		{
			printf("\n%d",L[i]);
			C = (uint32_t)((key & ((uint64_t)(1) << L[i])) >> (L[i]+i-27)) | C;
			printf(" %X",C);
		}
			
	}*/

	return C;			
}

uint32_t initial_permuted_choice_right(uint64_t key)
{
	uint16_t i;
	uint32_t D = 0;
	
	uint16_t R[28] = {63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};

	/*for(i=0;i<27;i++)
	{
		if((R[i]-i) > 0)
		{
			D = (uint32_t)((key & ((uint64_t)(1) << R[i])) >> (R[i]-i)) | D;	
		}
		else
		{
			D = (uint32_t)((key & ((uint64_t)(1) << R[i])) << (i-R[i])) | D;	
		}
	}*/	
	for(i=0;i<28;i++)
	{
		if((27 - i - (64-R[i])) > 0)
		{
			D = (uint32_t)((key & ((uint64_t)(1) << (64 - R[i]))) << (27 - i - (64 - R[i]))) | D;	
		}
		else
		{
			D = (uint32_t)((key & ((uint64_t)(1) << (64 - R[i]))) >> (64 - R[i] - (27 - i))) | D;	
		}
	}
	return D;			
}

uint32_t rotate_val_left(uint32_t val,uint16_t round)
{
	uint32_t rot_val = 0;
	uint16_t rot_amt[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

	rot_val = rot_val | ((val<<rot_amt[round-1]) | (val>>(28-rot_amt[round-1]))) & (0x0FFFFFFF);

	return rot_val;
}

uint64_t DES_key(uint64_t block)
{
	uint16_t i;
	uint64_t key = 0;
	
	uint16_t PC_2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,\
	                	 23,19,12,4,26,8,16,7,27,20,13,2,\
						 41,52,31,37,47,55,30,40,51,45,33,48,\
						 44,49,39,56,34,53,46,42,50,36,29,32};
	
	for(i=0;i<48;i++)
	{

		if((47 - i - (56-PC_2[i])) > 0)
		{
			key = (uint64_t)((block & ((uint64_t)(1) << (56 - PC_2[i]))) << (47 - i - (56 - PC_2[i]))) | key;	
		}
		else
		{
			key = (uint64_t)((block & ((uint64_t)(1) << (56 - PC_2[i]))) >> (56 - PC_2[i] - (47 - i))) | key;	
		}
		
	}
	
	return key;
}
	


