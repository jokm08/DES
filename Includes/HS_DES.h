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

#ifndef HS_DES_H
#define HS_DES_H

/*Type def*/
typedef char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

/*Function Declaration*/

uint32_t initial_permutation_left_32bit(uint64_t input_block_64bit);
uint32_t initial_permutation_right_32bit(uint64_t input_block_64bit);
uint64_t expansion_block(uint32_t right_block);
uint32_t substitution_function(uint64_t block);
uint32_t exclusive_Or(uint32_t left,uint32_t right_processed);
uint64_t inverse_initial_permutation(uint32_t left, uint32_t right);
uint32_t DES_F_Function(uint32_t Block_R, uint64_t Key);

#endif
