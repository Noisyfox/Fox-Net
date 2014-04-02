#include "precomp.h"

void processPPPOE(PNET_BUFFER pCurrentNetBuffer){
	BOOLEAN				bFalse = FALSE;
	PMDL                pMdl;
	ULONG               ulOffset;
	struct ether_header *pEthHeader = NULL;
	ULONG               ulBufferLength = 0;
	ULONG               NBDO;
	ULONG               NBDL;

	pMdl = NET_BUFFER_CURRENT_MDL(pCurrentNetBuffer);
	ulOffset = NET_BUFFER_CURRENT_MDL_OFFSET(pCurrentNetBuffer);
	NBDL = NET_BUFFER_DATA_LENGTH(pCurrentNetBuffer);
	NBDO = NET_BUFFER_DATA_OFFSET(pCurrentNetBuffer);
	do
	{
		ASSERT(pMdl != NULL);
		if (pMdl)
		{
			NdisQueryMdl(
				pMdl,
				&pEthHeader,
				&ulBufferLength,
				NormalPagePriority);
		}
		if (NULL == pEthHeader)
		{
			//  
			//  The system is low on resources. Set up to handle failure  
			//  below.  
			//  
			ulBufferLength = 0;
			break;
		}

		if (0 == ulBufferLength)
		{
			break;
		}

		ASSERT(ulBufferLength > ulOffset);
		ulBufferLength -= ulOffset;
		pEthHeader = (struct ether_header *)((PUCHAR)pEthHeader + ulOffset);

		if (ulBufferLength < sizeof(struct ether_header))
		{
			//KdPrint(
			//	("ReceiveNetBufferList: runt nbl %p, first buffer length %d\n",
			//	CurrNbl, ulBufferLength));
			break;
		}
		//KdPrint(("DstMAC: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", pEthHeader->ether_dhost[0], pEthHeader->ether_dhost[1], pEthHeader->ether_dhost[2], pEthHeader->ether_dhost[3], pEthHeader->ether_dhost[4], pEthHeader->ether_dhost[5]));
		//KdPrint(("SrcMAC: %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", pEthHeader->ether_shost[0], pEthHeader->ether_shost[1], pEthHeader->ether_shost[2], pEthHeader->ether_shost[3], pEthHeader->ether_shost[4], pEthHeader->ether_shost[5]));
		// 验证pppoe
		{
			UCHAR tl = pEthHeader->ether_type & 0xff;
			UCHAR th = (pEthHeader->ether_type >> 8) & 0xff;
			KdPrint(("Type  : %.2x%.2x\n", tl, th));
			//if (0x8864 == pEthHeader->ether_type || 0x6388 == pEthHeader->ether_type)KdPrint(("Is PPPOE!\n"));

			if (0x6488 == pEthHeader->ether_type){// pppoe session
				PPPPOE_SESSION pPPPOESession = (PPPPOE_SESSION)(((PUCHAR)pEthHeader) + sizeof(struct  ether_header));
				USHORT length = 0;
				KdPrint(("Is PPPOE session!\n"));
				ulBufferLength -= sizeof(struct  ether_header);
				if (ulBufferLength < sizeof(PPPOE_SESSION))
				{
					break;
				}
				length = ((pPPPOESession->length & 0xff) << 8) | ((pPPPOESession->length >> 8) & 0xff); // ppp包长度
				//解析剩余的PPPOE头
				//获取下一个MDL
				{
					PPPPOE pPPPOEHeader = NULL;
					PMDL nextMdl = NET_BUFFER_NEXT_NB(pMdl);
					if (nextMdl == NULL)break;

					NdisQueryMdl(
						nextMdl,
						&pPPPOEHeader,
						&ulBufferLength,
						NormalPagePriority);

					if (NULL == pPPPOEHeader)
					{
						break;
					}

					if (0 == ulBufferLength)
					{
						break;
					}

					ASSERT(ulBufferLength >= length);
					ASSERT(ulBufferLength >= sizeof(PPPOE));

					if (0x23c2 == pPPPOEHeader->protocol){
						PPPP_CHAP pChap = (PPPP_CHAP)(((PUCHAR)pPPPOEHeader) + sizeof(PPPOE));
						KdPrint(("CHAP found!\n"));
						ulBufferLength -= sizeof(PPPOE);
						if (ulBufferLength < sizeof(PPPP_CHAP))
						{
							break;
						}
						if (0x2 == pChap->code)
						{
							KdPrint(("Response!\n"));
							if (pChap->value_size == 0x10)
							{
								// 判断name是否是有前缀
								PUCHAR pName = (&pChap->value) + pChap->value_size;
								if (pName + 0x1 > (((PUCHAR)pChap) + pChap->length))
								{
									break;
								}
								if (pName[0] != '^' || pName[1] != '#')
								{
									break;
								}
								//hack!
								NewChapSecondMd5(&pChap->value);
								KdPrint(("Response hacked!\n"));
							}
						}
					}
				}
			}
		}
	} while (bFalse);
	//KdPrint(("End one NB process!\n"));
}
