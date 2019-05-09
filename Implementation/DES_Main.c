/********************************************************************/
/*                                                                  */
/*                       DES Main Function                          */
/*                                                                  */
/* Date        : 2/10/2019                                          */
/* Author(s)   : Jose Kurian Manooparambil, Tenzing Rabgyal         */
/* Course      : Introduction to Hardware Security and Trust        */
/* Institution : Tandon School of Engineering, New York University  */
/*                                                                  */
/********************************************************************/

#include<stdlib.h>
#include<stdio.h>
#include"HS_DESKey.h"
#include"HS_DES.h"

int main()
{
	uint16_t i;
	uint32_t F,Block_L, Block_R, temp, C_L, D_R;
	uint64_t input, key_64bit,val_64bit, block_56bit = 0, key_48bit, cipherText;
	
	printf("               DES");
	printf("\n               ===");
	
	printf("\nEnter the 64 bit key :");
	scanf("%llx",&key_64bit);
	
	printf("\nEnter the value to be Encoded :");
	scanf("%llx",&val_64bit);
	
	/*Initial Permuted Choice - key - Left*/
	C_L = initial_permuted_choice_left(key_64bit);
	
	/*Initial Permuted Choice - key - Right*/
	D_R = initial_permuted_choice_right(key_64bit);
	
	/*Initial Permuted Choice - Block - Left*/
	Block_L = initial_permutation_left_32bit(val_64bit);
	
	/*Initial Permuted Choice - Block - Right*/
	Block_R = initial_permutation_right_32bit(val_64bit);
		
	
	for(i=1;i<=16;i++)
	{
		printf("\n\n%d : Block L = %X Block R = %X",i-1,Block_L,Block_R);
		printf("\nC = %X D = %X",C_L,D_R);
	
		C_L = rotate_val_left(C_L,i);
		D_R = rotate_val_left(D_R,i);
		
		block_56bit = 0;
		block_56bit = block_56bit | (uint64_t)C_L;
		
		block_56bit = block_56bit << 28;
		
		block_56bit = block_56bit | (uint64_t)D_R;
		
		key_48bit = DES_key(block_56bit);
		
		printf("\n56 bit Key %llx",block_56bit);
		
		printf("\nKey-(%d) 48 bit : %llX",i+1,key_48bit);
		
		F = DES_F_Function(Block_R,key_48bit);
				
		temp = Block_L ^ F;
		
		if(i<16)
		{
			Block_L = Block_R;
			Block_R = temp; 
		}	
		else
		{
			Block_L = temp;	
		}					
	}
	
	printf("\n%d : Block L = %X Block R = %X",i-1,Block_L,Block_R);
		
	cipherText = inverse_initial_permutation(Block_L,Block_R);
	
	printf("\nEncrypted Value : %llX",cipherText);
		
	return 0;
		
}
