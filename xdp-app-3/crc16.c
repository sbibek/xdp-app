#include<stdio.h>
#include<stdint.h>
// #include<stdbool.h>
// #include "common_kern_user.h"

#include <linux/bpf.h>
#include "common_kern_user.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>



#define		CRC_START_16		0x0000
#define		CRC_POLY_16		0xA001

static bool             crc_tab16_init          = false;
static uint16_t         crc_tab16[256];

static void init_crc16_tab( void ) {

	uint16_t i;
	uint16_t j;
	uint16_t crc;
	uint16_t c;

	for (i=0; i<256; i++) {
		crc = 0;
		c   = i;
		for (j=0; j<8; j++) {
			if ( (crc ^ c) & 0x0001 ) crc = ( crc >> 1 ) ^ CRC_POLY_16;
			else                      crc =   crc >> 1;
			c = c >> 1;
		}
		crc_tab16[i] = crc;
	}
	crc_tab16_init = true;
} 



uint16_t crc_16( const unsigned char *input_str, size_t num_bytes, uint16_t *prev_crc ) {

	uint16_t crc;
	const unsigned char *ptr;
	size_t a;

 

	if ( ! crc_tab16_init ) init_crc16_tab();
    
    if(prev_crc) {
        crc = *prev_crc;
    } else 
    	crc = CRC_START_16;

	ptr = input_str;

	if ( ptr != NULL ) for (a=0; a<num_bytes; a++) {

		crc = (crc >> 8) ^ crc_tab16[ (crc ^ (uint16_t) *ptr++) & 0x00FF ];
	}

	return crc;

} 


unsigned long checksum_update(unsigned char *buf, int bufsz, unsigned long *prev_checksum) {
    unsigned long sum = 0;

    if(prev_checksum) {
        sum = (*prev_checksum);
    }

    while (bufsz > 0) {
        sum += *buf;
        buf++;
        bufsz -= 1;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return sum;
}

unsigned short get_checksum(unsigned long *val) {
    return ~(*val);
}

static inline unsigned short _checksum(unsigned char *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 0) {
   printf("%lu -> ",sum);
        sum += *buf;
        buf++;
        bufsz -= 1;

        sum = (sum & 0xffff) + (sum >> 16);
      sum = (sum & 0xffff) + (sum >> 16);
        printf("%lu\n",sum);
    }

    // if (bufsz == 1) {
    //     sum += *(unsigned char *)buf;
    // }


    return ~sum;
}


struct test {
    __u8 a,b,c,d;
};


int main(){
//     void *test1 = "1";
//     void *test2 = "2";
//     void *test3 = "3";
//     void *test4 = "4";
//     void *test5 = "123";
//     unsigned long _t = checksum(test1, 1, ((void *)0)) ;
//      _t = checksum(test2, 1, &_t) ;
//  _t = checksum(test3, 1, &_t) ;
//     unsigned short t = ~_t;
//     printf("%u, %u\n", t, _checksum(test5,3));

    // printf("%ld", sizeof(struct flows_info));


    // __u32 sum = 123456;

    // while (sum>>16)
    // sum = (sum & 0xFFFF) + (sum >> 16);

    // printf("%d", sum>>16);

    // return 0;

    void *test = "1234";
    __u8 *current = test;
    void *end = current + 4;
    // printf("%lu", end-current);

    struct test *t = (void *)current;


    printf("%u", *(__u8 *)end);
   
    // for(int i=0;i<4;i++){
    //     printf("%d => %u\n",i, *current);
    //     ++current;
    // }
    return 0;
}



// 4.1  "C"

//    The following "C" code algorithm computes the checksum with an inner
//    loop that sums 16-bits at a time in a 32-bit accumulator.

//    in 6
//        {
//            /* Compute Internet Checksum for "count" bytes
//             *         beginning at location "addr".
//             */
//        register long sum = 0;

//         while( count > 1 )  {
//            /*  This is the inner loop */
//                sum += * (unsigned short) addr++;
//                count -= 2;
//        }

//            /*  Add left-over byte, if any */
//        if( count > 0 )
//                sum += * (unsigned char *) addr;

//            /*  Fold 32-bit sum to 16 bits */
//        while (sum>>16)
//            sum = (sum & 0xffff) + (sum >> 16);

//        checksum = ~sum;
//    }


