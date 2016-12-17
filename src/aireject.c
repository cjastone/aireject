/*
 *  802.11 WEP replay & injection attacks
 *
 *  Copyright (C) 2006-2016 Thomas d'Otreppe <tdotreppe@aircrack-ng.org>
 *  Copyright (C) 2004, 2005 Christophe Devine
 * 
 *  aireject 0.1 modifications December 2016 by Chris Stone 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if defined(linux)
    #include <linux/rtc.h>
#endif

#include <sys/ioctl.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <limits.h>

#include "version.h"
#include "osdep/osdep.h"
#include "crypto.h"
#include "common.h"

#define RTC_RESOLUTION  8192
#define MAX_APS     200		// max number of access points
#define UPPER_CHAN  13		// highest available 2.4 channel
#define DELAY		0.5		// delay between channel hops (s)

#define AUTH_REQ        \
    "\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"

#define NULL_DATA       \
    "\x48\x01\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B"

#define RTS             \
    "\xB4\x00\x4E\x04\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"

#define RATES           \
    "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ       \
    "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

#define RATE_NUM 12

#define RATE_1M 1000000
#define RATE_2M 2000000
#define RATE_5_5M 5500000
#define RATE_11M 11000000

#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

int bitrates[RATE_NUM]={RATE_1M, RATE_2M, RATE_5_5M, RATE_6M, RATE_9M, RATE_11M, RATE_12M, RATE_18M, RATE_24M, RATE_36M, RATE_48M, RATE_54M};

extern int maccmp(unsigned char *mac1, unsigned char *mac2);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);

char usage[] =
"\n"
"  %s - (C) 2006-2015 Thomas d\'Otreppe\n"
"  http://www.aircrack-ng.org\n"
"\n"
"  aireject 0.1 modifications November 2016 by Chris Stone\n"
"  https://github.com/cjastone/aireject\n"
"\n"
"  usage: aireject <options> <wlan interface>\n"
"\n"
"  Options:\n"
"\n"
"      -b bssid  : MAC address of target AP\n"
"      -c n      : channel on which to search for target, 0 to hop\n"
"      -r n      : number of requests to send per AP\n"
"      -t n      : timeout in seconds when waiting for AP beacons\n"
"      -B        : activates the bitrate test\n"
"\n"
"  Miscellaneous options:\n"
"\n"
"      --test              : tests injection and quality (-9)\n"
"      --help              : Displays this usage screen\n"
"\n";

struct options
{
    unsigned char t_bssid[6];
    unsigned char r_bssid[6];
    unsigned char r_smac[6];

    char *iface_out;

	unsigned int timeout;
    int requests;
    int channel;
    int bittest;
    int rtc;
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    unsigned char mac_in[6];
    unsigned char mac_out[6];
}
dev;

static struct wif *_wi_in, *_wi_out;

struct APt
{
    unsigned char set;
    unsigned short int found;
    unsigned char len;
    unsigned char essid[255];
    unsigned char bssid[6];
    unsigned char chan;
    unsigned int ping[32767];  // CS SUPER HACKY WORKAROUND
    int pwr[32767];		// CS IDEALLY WOULD BE ABLE TO GET FROM ARGS, BUT NO EASY WAY WITHOUT CODE REWRITE
};

struct APt ap[MAX_APS];

unsigned long nb_pkt_sent;
unsigned char h80211[4096];

int set_bitrate(struct wif *wi, int rate)
{
    int i, newrate;

    if( wi_set_rate(wi, rate) )
        return 1;

    //Workaround for buggy drivers (rt73) that do not accept 5.5M, but 5M instead
    if (rate == 5500000 && wi_get_rate(wi) != 5500000) {
	if( wi_set_rate(wi, 5000000) )
	    return 1;
    }

    newrate = wi_get_rate(wi);
    for(i=0; i<RATE_NUM; i++)
    {
        if(bitrates[i] == rate)
            break;
    }
    if(i==RATE_NUM)
        i=-1;
    if( newrate != rate )
    {
        if(i!=-1)
        {
            if( i>0 )
            {
                if(bitrates[i-1] >= newrate)
                {
                    printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/
#if defined(__x86_64__) && defined(__CYGWIN__)
			(0.0f + 1000000)),
#else
			1000000.0),
#endif
			(wi_get_rate(wi)/
#if defined(__x86_64__) && defined(__CYGWIN__)
			(0.0f + 1000000)
#else
			1000000.0
#endif
			));
                    return 1;
                }
            }
            if( i<RATE_NUM-1 )
            {
                if(bitrates[i+1] <= newrate)
                {
                    printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/
#if defined(__x86_64__) && defined(__CYGWIN__)
			(0.0f + 1000000)),
#else
			1000000.0),
#endif
			 (wi_get_rate(wi)/
#if defined(__x86_64__) && defined(__CYGWIN__)
			(0.0f + 1000000)));
#else
			1000000.0));
#endif
                    return 1;
                }
            }
            return 0;
        }
        printf("Couldn't set rate to %.1fMBit. (%.1fMBit instead)\n", (rate/
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 1000000)),
#else
		1000000.0),
#endif
		(wi_get_rate(wi)/
#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 1000000)));
#else
		1000000.0));
#endif

        return 1;
    }
    return 0;
}

int send_packet(void *buf, size_t count)
{
	struct wif *wi = _wi_out; // XXX globals suck
	unsigned char *pkt = (unsigned char*) buf;

	if( (count > 24) && (pkt[1] & 0x04) == 0 && (pkt[22] & 0x0F) == 0)
	{
		pkt[22] = (nb_pkt_sent & 0x0000000F) << 4;
		pkt[23] = (nb_pkt_sent & 0x00000FF0) >> 4;
	}

	if (wi_write(wi, buf, count, NULL) == -1) {
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			usleep(10000);
			return 0; // XXX not sure I like this... -sorbo 
		}

		perror("wi_write()");
		return -1;
	}

	nb_pkt_sent++;
	return 0;
}

int read_packet(void *buf, size_t count, struct rx_info *ri)
{
	struct wif *wi = _wi_in; // XXX 
	int rc;

        rc = wi_read(wi, buf, count, ri);
        if (rc == -1) {
            switch (errno) {
            case EAGAIN:
                    return 0;
            }

            perror("wi_read()");
            return -1;
        }

	return rc;
}

int grab_essid(unsigned char* packet, int len)
{
    int i=0, j=0, pos=0, tagtype=0, taglen=0, chan=0;
    unsigned char bssid[6];

    memcpy(bssid, packet+16, 6);
    taglen = 22;    //initial value to get the fixed tags parsing started
    taglen+= 12;    //skip fixed tags in frames
    do
    {
        pos    += taglen + 2;
        tagtype = packet[pos];
        taglen  = packet[pos+1];
    } while(tagtype != 3 && pos < len-2);

    if(tagtype != 3) return -1;
    if(taglen != 1) return -1;
    if(pos+2+taglen > len) return -1;

    chan = packet[pos+2];

    pos=0;

    taglen = 22;    //initial value to get the fixed tags parsing started
    taglen+= 12;    //skip fixed tags in frames
    do
    {
        pos    += taglen + 2;
        tagtype = packet[pos];
        taglen  = packet[pos+1];
    } while(tagtype != 0 && pos < len-2);

    if(tagtype != 0) return -1;
    if(taglen > 250) taglen = 250;
    if(pos+2+taglen > len) return -1;

    for(i=0; i<MAX_APS; i++)	// CS CHANGED FIXED VALUE OF 20 TO MAX_APS
    {
        if( ap[i].set)
        {
            if( memcmp(bssid, ap[i].bssid, 6) == 0 )    //got it already
            {
                if(packet[0] == 0x50 && !ap[i].found)
                {
                    ap[i].found++;
                }
                if(ap[i].chan == 0) ap[i].chan=chan;
                break;
            }
        }
        if(ap[i].set == 0)
        {
            for(j=0; j<taglen; j++)
            {
                if(packet[pos+2+j] < 32 || packet[pos+2+j] > 127)
                {
                    return -1;
                }
            }

            ap[i].set = 1;
            ap[i].len = taglen;
            memcpy(ap[i].essid, packet+pos+2, taglen);
            ap[i].essid[taglen] = '\0';
            memcpy(ap[i].bssid, bssid, 6);
            ap[i].chan = chan;
            if(packet[0] == 0x50) ap[i].found++;
            return 0;
        }
    }
    return -1;
}

int do_attack_test()
{
    unsigned char packet[4096];
    struct timeval tv, tv2, tv3, tv4, tv5;
    int len=0, i=0, j=0, k=0;
    int gotit=0, answers=0, found=0;
    int caplen=0;
    unsigned int min, avg, max;
    float avg2;
    struct rx_info ri;
    unsigned long atime=200;  //time in ms to wait for answer packet (needs to be higher for airserv)
    unsigned char nulldata[1024];
    int working = 0;
    int macindex = -1;	// CS INDEX OF SPECIFIED BSSID
    unsigned int chanindex = 0; 	// CS INDEX OF CHANNEL FOR HOPPING
	
    /* avoid blocking on reading the socket */
    if( fcntl( dev.fd_in, F_SETFL, O_NONBLOCK ) < 0 )
    {
        perror( "fcntl(O_NONBLOCK) failed" );
        return( 1 );
    }

    srand( time( NULL ) );

    memset(ap, '\0', MAX_APS*sizeof(struct APt));	// CS CHANGED FIXED VALUE OF 20 TO MAX_APS
    
    wi_set_channel(_wi_out, opt.channel);	// CS SET INTERFACE TO SPECIFIED CHANNEL

    if(opt.bittest)
        set_bitrate(_wi_out, RATE_1M);
    
	if( memcmp( opt.t_bssid, NULL_MAC, 6 ) != 0 )
	{
		PCT; printf("Waiting for target BSSID...\n\n");
	}
	else
	{
		PCT; printf("Trying broadcast probe requests...\n\n");
	}
	
    memcpy(h80211, PROBE_REQ, 24);

    len = 24;

    h80211[24] = 0x00;      //ESSID Tag Number
    h80211[25] = 0x00;      //ESSID Tag Length

    len += 2;

    memcpy(h80211+len, RATES, 16);

    len += 16;

    gotit=0;
    answers=0;
    for(i=0; i<3; i++)
    {
        /* random source so we can identify our packets */
        opt.r_smac[0] = 0x00;
        opt.r_smac[1] = rand() & 0xFF;
        opt.r_smac[2] = rand() & 0xFF;
        opt.r_smac[3] = rand() & 0xFF;
        opt.r_smac[4] = rand() & 0xFF;
        opt.r_smac[5] = rand() & 0xFF;

        memcpy(h80211+10, opt.r_smac, 6);

        send_packet(h80211, len);

        gettimeofday( &tv, NULL );
        gettimeofday( &tv4, NULL );

        
        wi_set_channel(_wi_out, chanindex); // CS SET INITIAL CHANNEL

        while (1)  //waiting for relayed packet
        {
            caplen = read_packet(packet, sizeof(packet), &ri);

            if (packet[0] == 0x50 ) //Is probe response
            {
                if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
                {
                    if(grab_essid(packet, caplen) == 0 && (!memcmp(opt.r_bssid, NULL_MAC, 6)))
                    {
                        found++;
                        i = found - 1;
                        PCT; printf("P  %02X:%02X:%02X:%02X:%02X:%02X\tCh: %u\t%s\n", ap[i].bssid[0], ap[i].bssid[1],
							ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5], ap[i].chan, ap[i].essid);
                    }
                    if(!answers)
                    {
                        //PCT; printf("Injection is working!\n");
                        working = 1;
                        gotit=1;
                        answers++;
                    }
                }
            }

            if (packet[0] == 0x80 ) //Is beacon frame
            {
                if(grab_essid(packet, caplen) == 0 && (!memcmp(opt.r_bssid, NULL_MAC, 6)))
                {
                    found++;
                    //PCT; printf("Found %d AP%c\n", found, ((found == 1) ? ' ' : 's' )); // CS GIVE REALTIME FEEDBACK ON APS FOUND);
                    i = found - 1;
                    PCT; printf("B  %02X:%02X:%02X:%02X:%02X:%02X\tCh: %u\t%s\n", ap[i].bssid[0], ap[i].bssid[1],
						ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5], ap[i].chan, ap[i].essid);
                }
            }

            gettimeofday( &tv2, NULL );
            gettimeofday( &tv5, NULL );
            
            //printf("%02X:%02X:%02X:%02X:%02X:%02x\n", ap[i].bssid[0], ap[i].bssid[1], ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5]);
            
			if( memcmp( opt.t_bssid, NULL_MAC, 6 ) != 0 )	// CS CHECK IF BSSID SPECIFIED
			{
				if( maccmp( opt.t_bssid, ap[i].bssid) == 0 )	// CS CHECK FOR BSSID MATCH
				{
					printf("\n");
					PCT; printf("BSSID found: %02X:%02X:%02X:%02X:%02X:%02x", ap[i].bssid[0], ap[i].bssid[1], ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5]);
					macindex = i;
					break;
				}
			}
			
			if ( macindex != -1)
			{
				break;
			}
			
			if ((((tv5.tv_sec*1000000UL - tv4.tv_sec*1000000UL) + (tv5.tv_usec - tv4.tv_usec)) > ( DELAY * 1000000)) && opt.channel == 0)	// CS IMPLEMENTATION OF CHANNEL HOPPING
			{
				chanindex+=1; 
				chanindex = (chanindex < 1) ? UPPER_CHAN : (chanindex > UPPER_CHAN) ? 1 : chanindex;	// CS WRAP CHANINDEX TO MIN/MAX VALUES
				
				PCT; printf("Switching to channel:\t%d\n", chanindex);
				wi_set_channel(_wi_out, chanindex);
				gettimeofday( &tv4, NULL );	// CS RESET TIMER REFERENCE
			}
			
            if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > ( opt.timeout * 1000000)) // CS WAIT UNTIL SPECIFIED TIMEOUT TO CAPTURE APS
            {
                break;
            }
        }
    }
    if(answers == 0)
    {
        printf("\n"); PCT; printf("No answer to probe requests...\n");
    }
    
    if (working)	// CS NOTIFY AT END SO AS TO NOT INTERRUPT SSID LIST
    {
		printf("\n"); PCT; printf("Injection is working!\n");	
	}
	
	
	
    PCT; printf("Found %d AP%c\n", found, ((found == 1) ? ' ' : 's' ) );

	if(macindex == -1 && memcmp( opt.t_bssid, NULL_MAC, 6 ) != 0)
	{
		printf("\n"); PCT; printf("Target BSSID not seen.\n");
		return 0;
	}

    if(found > 0)
    {
        printf("\n"); PCT; printf("Trying directed probe requests...\n");	
    }

    for(i=0; i<found; i++)
    {
		if(macindex == -1 || macindex == i )	// CS ONLY TARGET BSSID IF SPECIFIED
		{		
			if(wi_get_channel(_wi_out) != ap[i].chan)
			{
				wi_set_channel(_wi_out, ap[i].chan);
			}

			if(wi_get_channel(_wi_in) != ap[i].chan)
			{
				wi_set_channel(_wi_in, ap[i].chan);
			}

			printf("\n"); PCT; printf("Channel: %d\t  %02X:%02X:%02X:%02X:%02X:%02X   \'%s\'\n", ap[i].chan, ap[i].bssid[0], ap[i].bssid[1],
					ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5], ap[i].essid);
					
			ap[i].found=0;
			min = INT_MAX;
			max = 0;
			avg = 0;
			avg2 = 0;

			memcpy(h80211, PROBE_REQ, 24);

			len = 24;

			h80211[24] = 0x00;      //ESSID Tag Number
			h80211[25] = ap[i].len; //ESSID Tag Length
			memcpy(h80211+len+2, ap[i].essid, ap[i].len);

			len += ap[i].len+2;

			memcpy(h80211+len, RATES, 16);

			len += 16;

			for(j=0; j<opt.requests; j++)
			{
				/* random source so we can identify our packets */
				opt.r_smac[0] = 0x00;
				opt.r_smac[1] = rand() & 0xFF;
				opt.r_smac[2] = rand() & 0xFF;
				opt.r_smac[3] = rand() & 0xFF;
				opt.r_smac[4] = rand() & 0xFF;
				opt.r_smac[5] = rand() & 0xFF;

				//build/send probe request
				memcpy(h80211+10, opt.r_smac, 6);

				send_packet(h80211, len);
				usleep(10);

				//build/send request-to-send
				memcpy(nulldata, RTS, 16);
				memcpy(nulldata+4, ap[i].bssid, 6);
				memcpy(nulldata+10, opt.r_smac, 6);

				send_packet(nulldata, 16);
				usleep(10);

				//build/send null data packet
				memcpy(nulldata, NULL_DATA, 24);
				memcpy(nulldata+4, ap[i].bssid, 6);
				memcpy(nulldata+10, opt.r_smac, 6);
				memcpy(nulldata+16, ap[i].bssid, 6);

				send_packet(nulldata, 24);
				usleep(10);

				//build/send auth request packet
				memcpy(nulldata, AUTH_REQ, 30);
				memcpy(nulldata+4, ap[i].bssid, 6);
				memcpy(nulldata+10, opt.r_smac, 6);
				memcpy(nulldata+16, ap[i].bssid, 6);

				send_packet(nulldata, 30);

				//continue
				gettimeofday( &tv, NULL );

				printf( "\rPackets Rx/Tx: %2d/%2d:   %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));  //this is where the overflow happens -  ap[i].found
				fflush(stdout);
				while (1)  //waiting for relayed packet
				{
					caplen = read_packet(packet, sizeof(packet), &ri);

					if (packet[0] == 0x50 ) //Is probe response
					{
						if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
						{
							if(! memcmp(ap[i].bssid, packet+16, 6)) //From the mentioned AP
							{
								gettimeofday( &tv3, NULL);
								ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
								if(!answers)
								{
									answers++;
								}
								ap[i].found++;
								if((signed)ri.ri_power > -200)
									ap[i].pwr[j] = (signed)ri.ri_power;
								break;
							}
						}
					}

					if (packet[0] == 0xC4 ) //Is clear-to-send
					{
						if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
						{
							gettimeofday( &tv3, NULL);
							ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
							if(!answers)
							{	
								answers++;
							}
							ap[i].found++;
							if((signed)ri.ri_power > -200)
								ap[i].pwr[j] = (signed)ri.ri_power;
							break;
						}
					}

					if (packet[0] == 0xD4 ) //Is ack
					{
						if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
						{
							gettimeofday( &tv3, NULL);
							ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
							if(!answers)
							{
								answers++;
							}
							ap[i].found++;
							if((signed)ri.ri_power > -200)
								ap[i].pwr[j] = (signed)ri.ri_power;
							break;
						}
					}

					if (packet[0] == 0xB0 ) //Is auth response
					{
						if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
						{
							if (! memcmp(packet+10, packet+16, 6)) //From BSS ID
							{
								gettimeofday( &tv3, NULL);
								ap[i].ping[j] = ((tv3.tv_sec*1000000 - tv.tv_sec*1000000) + (tv3.tv_usec - tv.tv_usec));
								if(!answers)
								{
									answers++;
								}
								ap[i].found++;
								if((signed)ri.ri_power > -200)
									ap[i].pwr[j] = (signed)ri.ri_power;
								break;
							}
						}
					}

					gettimeofday( &tv2, NULL );
					if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (atime*1000)) //wait 'atime'ms for an answer
					{
						break;
					}
					usleep(10);
				}
				PCT; printf( "\rPackets Rx/Tx: %2d/%2d:  %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));
				fflush(stdout);
			}
			for(j=0; j<opt.requests; j++)
			{
				if(ap[i].ping[j] > 0)
				{
					if(ap[i].ping[j] > max) max = ap[i].ping[j];
					if(ap[i].ping[j] < min) min = ap[i].ping[j];
					avg += ap[i].ping[j];
					avg2 += ap[i].pwr[j];
				}
			}
			if(ap[i].found > 0)
			{
				avg /= ap[i].found;
				avg2 /= ap[i].found;
				PCT; printf("Power: %.2f   Ping (min/avg/max): %.3fms/%.3fms/%.3fms\n",
#if defined(__x86_64__) && defined(__CYGWIN__)
	avg2, (min/(0.0f + 1000)), (avg/(0.0f + 1000)), (max/(0.0f + 1000)));
#else
	avg2, (min/1000.0), (avg/1000.0), (max/1000.0));
#endif
			}
			PCT; printf("Packets Rx/Tx:  %2d/%2d:  %3d%%\n", ap[i].found, opt.requests, ((ap[i].found*100)/opt.requests));

			if(!gotit && answers)
			{
				//PCT; printf("Injection is working!\n\n");
				working = 1;
				gotit=1;
			}
		}
	}

	if(opt.bittest)
	{
		if(found > 0)
		{
			printf("\n"); PCT; printf("Trying directed probe requests for all bitrates...\n");
		}

		for(i=0; i<found; i++)
		{
			if(macindex == -1 || macindex == i)	// CS ONLY TARGET BSSID IF SPECIFIED
			{	
				printf("\n");
				PCT; printf("Channel: %d\t  %02X:%02X:%02X:%02X:%02X:%02X   \'%s\'\n", ap[i].chan, ap[i].bssid[0], ap[i].bssid[1],
						ap[i].bssid[2], ap[i].bssid[3], ap[i].bssid[4], ap[i].bssid[5], ap[i].essid);

				min = INT_MAX;
				max = 0;
				avg = 0;

				memcpy(h80211, PROBE_REQ, 24);

				len = 24;

				h80211[24] = 0x00;      //ESSID Tag Number
				h80211[25] = ap[i].len; //ESSID Tag Length
				memcpy(h80211+len+2, ap[i].essid, ap[i].len);

				len += ap[i].len+2;

				memcpy(h80211+len, RATES, 16);

				len += 16;

				for(k=0; k<RATE_NUM; k++)
				{
					ap[i].found=0;
					if(set_bitrate(_wi_out, bitrates[k]))
						continue;


					avg2 = 0;
					memset(ap[i].pwr, 0, opt.requests*sizeof(unsigned int));

					for(j=0; j<opt.requests; j++)
					{
						/*
							random source so we can identify our packets
						*/
						opt.r_smac[0] = 0x00;
						opt.r_smac[1] = rand() & 0xFF;
						opt.r_smac[2] = rand() & 0xFF;
						opt.r_smac[3] = rand() & 0xFF;
						opt.r_smac[4] = rand() & 0xFF;
						opt.r_smac[5] = rand() & 0xFF;

						memcpy(h80211+10, opt.r_smac, 6);

						send_packet(h80211, len);

						gettimeofday( &tv, NULL );

						PCT; printf( "\rPackets Rx/Tx: %2d/%2d:   %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));
						fflush(stdout);
						while (1)  //waiting for relayed packet
						{
							caplen = read_packet(packet, sizeof(packet), &ri);

							if (packet[0] == 0x50 ) //Is probe response
							{
								if (! memcmp(opt.r_smac, packet+4, 6)) //To our MAC
								{
									if(! memcmp(ap[i].bssid, packet+16, 6)) //From the mentioned AP
									{
										if(!answers)
										{
											answers++;
										}
										ap[i].found++;
										if((signed)ri.ri_power > -200)
											ap[i].pwr[j] = (signed)ri.ri_power;
										break;
									}
								}
							}

							gettimeofday( &tv2, NULL );
							if (((tv2.tv_sec*1000000UL - tv.tv_sec*1000000UL) + (tv2.tv_usec - tv.tv_usec)) > (100*1000)) //wait 300ms for an answer
							{
								break;
							}
							usleep(10);
						}
						PCT; printf( "\rPackets Rx/Tx: %2d/%2d:   %3d%%\r", ap[i].found, j+1, ((ap[i].found*100)/(j+1)));
						fflush(stdout);
					}
					for(j=0; j<opt.requests; j++)
						avg2 += ap[i].pwr[j];
					if(ap[i].found > 0)
						avg2 /= ap[i].found;
					PCT; printf("Probing at %2.1f Mbps:\t%2d/%2d:   %3d%%\n", wi_get_rate(_wi_out)/
	#if defined(__x86_64__) && defined(__CYGWIN__)
		(0.0f + 1000000),
	#else
		1000000.0,
	#endif
					ap[i].found, opt.requests, (ap[i].found*100)/opt.requests);
				}

				if(!gotit && answers)
				{
					//PCT; printf("Injection is working!\n\n");  // move this so it doesn't interrupt ssid readout
					gotit=1;
				}
			}
		}
	}
    
    if(opt.bittest)
        set_bitrate(_wi_out, RATE_1M);

    return 0;
}

int main( int argc, char *argv[] )
{
    int ret;

    /* check the arguments */
    memset( &opt, 0, sizeof( opt ) );
    memset( &dev, 0, sizeof( dev ) );
    
    opt.bittest     =  0;
    opt.requests  =  30;	// CS SET DEFAULT NUMBER OF REQUESTS
    opt.rtc       =  1; 
    opt.timeout = 17;		// CS SET DEFAULT TIMEOUT

/* XXX */
#if 0
#if defined(__FreeBSD__)
    /*
        check what is our FreeBSD version. injection works
        only on 7-CURRENT so abort if it's a lower version.
    */
    if( __FreeBSD_version < 700000 )
    {
        fprintf( stderr, "Aireplay-ng does not work on this "
            "release of FreeBSD.\n" );
        exit( 1 );
    }
#endif
#endif

    while( 1 )
    {
        int option_index = 0;

        static struct option long_options[] = {
            {"help",        0, 0, 'H'},
            {"bittest",     0, 0, 'B'},
            {0,             0, 0,  0 }
        };

        int option = getopt_long( argc, argv, "b:c:t:r:B", long_options, &option_index );

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :

                break;

            case ':' :

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case '?' :

                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case 'b' :

                if( getmac( optarg, 1 ,opt.t_bssid ) != 0 )
                {
                    printf( "Invalid target BSSID.\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;
                
            case 'c' :	// CS ENABLE CHANNEL SPEC/HOPPING

                ret = sscanf( optarg, "%d", &opt.channel );
                if( opt.channel < 0 || opt.channel > 14 || ret != 1 )
                {
                    printf( "Invalid channel specified [1-14, 0 to hop]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;
                
            case 'r' :	// CS SPECIFY NUMBER OF PACKETS PER AP
            
                ret = sscanf( optarg, "%d", &opt.requests );	
                if( opt.requests <= 0 || opt.requests >= 32767 || ret != 1 )
                {
                    printf( "Invalid number of requests per AP [1-32767]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;
            
            case 't' :

                ret = sscanf( optarg, "%d", &opt.timeout );	// CS SPECIFY NUMBER TIMEOUTS WHEN SEARCHING FOR APS
                if( opt.timeout >= 2000 || ret != 1 )
                {
                    printf( "Invalid timeout length [1-2000]\n" );
                    printf("\"%s --help\" for help.\n", argv[0]);
                    return( 1 );
                }
                break;

            case 'B' :

                opt.bittest = 1;
                break;
                
            default : goto usage;
        }
    }

    if( argc - optind != 1 )
    {
    	if(argc == 1)
    	{
usage:
	        printf( usage, getVersion("Aireplay-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );
        }
	    if( argc - optind == 0)
	    {
	    	printf("No replay interface specified.\n");
	    }
	    if(argc > 1)
	    {
    		printf("\"%s --help\" for help.\n", argv[0]);
	    }
        return( 1 );
    }

    dev.fd_rtc = -1;

    /* open the RTC device if necessary */

#if defined(__i386__)
#if defined(linux)
	if( ( dev.fd_rtc = open( "/dev/rtc0", O_RDONLY ) ) < 0 )
	{
		dev.fd_rtc = 0;
	}

	if( (dev.fd_rtc == 0) && ( ( dev.fd_rtc = open( "/dev/rtc", O_RDONLY ) ) < 0 ) )
	{
		dev.fd_rtc = 0;
	}
	if(opt.rtc == 0)
	{
		dev.fd_rtc = -1;
	}
	if(dev.fd_rtc > 0)
	{
		if( ioctl( dev.fd_rtc, RTC_IRQP_SET, RTC_RESOLUTION ) < 0 )
		{
			perror( "ioctl(RTC_IRQP_SET) failed" );
			printf(
"Make sure enhanced rtc device support is enabled in the kernel (module\n"
"rtc, not genrtc) - also try 'echo 1024 >/proc/sys/dev/rtc/max-user-freq'.\n" );
			close( dev.fd_rtc );
			dev.fd_rtc = -1;
		}
		else
		{
			if( ioctl( dev.fd_rtc, RTC_PIE_ON, 0 ) < 0 )
			{
				perror( "ioctl(RTC_PIE_ON) failed" );
				close( dev.fd_rtc );
				dev.fd_rtc = -1;
			}
		}
	}
	else
	{
		printf( "For information, no action required:"
				" Using gettimeofday() instead of /dev/rtc\n" );
		dev.fd_rtc = -1;
	}

#endif /* linux */
#endif /* i386 */

    opt.iface_out = argv[optind];

    // open the replay interface
    _wi_out = wi_open(opt.iface_out); 	// CS BREAKS HERE IF WRONG IFACE SPECIFIED
    if (!_wi_out)
        return 1;
    dev.fd_out = wi_fd(_wi_out); 
		
    // open the packet source
    _wi_in = _wi_out;
    dev.fd_in = dev.fd_out;
    dev.arptype_in = dev.arptype_out;
    wi_get_mac(_wi_in, dev.mac_in);
    wi_get_mac(_wi_out, dev.mac_out);
    
    /* drop privileges */
    if (setuid( getuid() ) == -1) {
		perror("setuid");
	}

    memcpy( opt.r_smac, dev.mac_out, 6);

	do_attack_test();

    /* that's all, folks */

    return( 0 );
}
