#ifndef __COMMON_ABD_H
#define __COMMON_ABD_H

#include <linux/types.h>

#define ABD_UDP_PORT 4242 // UDP port for ABD messages

/* ABD message types */
enum abdmsg_type {
	ABD_WRITE = 0,
	ABD_WRITE_ACK,
	ABD_READ,
	ABD_READ_ACK
};

/* Struct for ABD messages */
struct abdmsg {
    __u8 type;
    __u32 tag;
    __u32 value;
    __u32 counter;
};

#endif /* __COMMON_ABD_H */
