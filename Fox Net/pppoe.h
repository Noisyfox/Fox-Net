#ifndef _PPPOE_H
#define _PPPOE_H

#define ETHER_ADDR_LEN      6   /* length of an Ethernet address */  
struct  ether_header {
	UCHAR   ether_dhost[ETHER_ADDR_LEN];
	UCHAR   ether_shost[ETHER_ADDR_LEN];
	USHORT  ether_type;
};

typedef struct _pppoe{
	USHORT protocol;
} PPPOE, *PPPPOE;

typedef struct _ppp_chap{
	UCHAR code;
	UCHAR identifier;
	USHORT length;
	UCHAR value_size;
	UCHAR value;
} PPP_CHAP, *PPPP_CHAP;

typedef struct _pppoe_session{
	UCHAR version_type;
	UCHAR code;
	USHORT session_id;
	USHORT length;
}PPPOE_SESSION, *PPPPOE_SESSION;

void processPPPOE(PNET_BUFFER pCurrentNetBuffer);

#endif  //_PPPOE_H
