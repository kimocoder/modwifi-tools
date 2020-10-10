#ifndef CRYPTO_H__
#define CRYPTO_H__

#include <stdint.h>

#include "eapol.h"
#include "ieee80211header.h"

#define PREPACK __attribute__ ((__packed__))

//
// Key configuration and EAPOL functions
//

/** calculate pairwise master key from passphrase and essid */
void calc_pmk(const char *psk, const char *essid, uint8_t pmk[32]);

/* derive the pairwise transcient keys from a bunch of stuff */
void calc_ptk(uint8_t bssid[8], uint8_t stmac[8], uint8_t anonce[32], uint8_t snonce[32],
              uint8_t pmk[32], uint8_t ptk[80]);

/** verify the MIC of an eapol message */
bool verify_mic(uint8_t *buf, size_t len, int keyver, uint8_t mic[16], uint8_t kck[16]);

/**
 * decrypt the WPA Key Data in an EAPOL handshake message
 *
 * len is the length of buf
 * out must be at least of size (len - 8)
 */
int decrypt_eapol_key_data(uint8_t iv[16], uint8_t kek[16], EapolKeyVer keyver, uint8_t *buf, uint8_t *out, size_t len);


//
// Packet decryption functions
//

/** WEP decryption/encryption functions */
bool encrypt_wep(uint8_t *data, size_t len, uint8_t wepseed[16]);
bool decrypt_wep(uint8_t *data, size_t len, uint8_t wepseed[16]);

/** calculate per packet key for TKIP */
int calc_tkip_ppk(uint8_t *buf, size_t len, uint8_t enckey8[16], uint8_t wepseed[16]);

/** decrypt a tkip packet in place */
int decrypt_tkip(uint8_t *buf, size_t len, uint8_t enckey[16], uint8_t *out);


int test_michael();

/** reverse Michael algorithm to get MIC key */
int calc_michael_key(uint8_t *buf, size_t len, uint8_t mickey[8]);

//
// CCMP header and decryption routines
//

#define CCMP_MAC_LEN 8

typedef struct PREPACK ccmp_hdr
{
	uint8_t pn0;
	uint8_t pn1;
	uint8_t rsvd;
	struct PREPACK key_id {
		uint8_t rsvd : 5;
		uint8_t ext_iv : 1; /** always set to 1 for CCMP */
		uint8_t key_id : 2;
	} key_id;
	uint8_t pn2;
	uint8_t pn3;
	uint8_t pn4;
	uint8_t pn5;

} ccmp_hdr;

typedef struct PREPACK ccmp_nonce
{
	struct PREPACK flags {
		uint8_t priority : 4;
		uint8_t management : 1;
		uint8_t zeros : 3;
	} flags;
	uint8_t a2[6]; /** The senders MAC address */
	//TODO Store them as octets?
	uint64_t pn : 48; /** The packet number from the CCMP header*/
} ccmp_nonce;

typedef struct ccmp_pkt
{
	ccmp_nonce nonce;
	/** 9.2.4.7 Frame Body field, Table 9-19 - Maximum MSDU size is 2302 bytes */
	// MIC field is 8 bytes
	uint8_t data[MAX_MSDU_BODY_SIZE + 8];
	uint16_t len;
} ccmp_pkt;

/** Two xored plaintext packets */
typedef struct ccmp_xored_pkt
{
	uint64_t pn;
	/** 9.2.4.7 Frame Body field, Table 9-19 - Maximum MSDU size is 2302 bytes */
	// MIC field is 8 bytes
	uint8_t data[MAX_MSDU_BODY_SIZE + 8];
} ccmp_xored_pkt;

/**
 * Reads the relevant values for the CCMP nonce from the ieee80211 and CCMP header
 * and writes them into nonce.
 *TODO Is only implemented for data frames, not for management or control frames.
 *
 */
void parse_ccmp_nonce(const uint8_t *buf, const size_t len, ccmp_nonce* nonce);

/**
 * Overload == operator for ccmp_nonce
 */
inline bool operator== (const ccmp_nonce& nl, const ccmp_nonce& nr)
{
	if (nl.flags.priority != nr.flags.priority)
		return false;

	if (nl.flags.management != nr.flags.management)
		return false;

	if (nl.flags.management != nr.flags.management)
		return false;

	for (uint8_t i=0; i<6; ++i)
	{
		if (nl.a2[i] != nr.a2[i])
			return false;
	}

	return nl.pn == nr.pn;
}

inline bool operator!= (const ccmp_nonce& nonce_lhs, const ccmp_nonce& nonce_rhs) { return !(nonce_lhs == nonce_rhs); };


#endif // CRYPTO_H__
