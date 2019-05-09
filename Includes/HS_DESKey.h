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

#ifndef HS_DESKey_H
#define HS_DESKey_H

/*Type def*/

typedef char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

/*Function Declaration*/

uint32_t initial_permuted_choice_left(uint64_t key);
uint32_t initial_permuted_choice_right(uint64_t key);
uint32_t rotate_val_left(uint32_t val,uint16_t round);
uint64_t DES_key(uint64_t block);

#endif
