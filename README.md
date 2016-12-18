# aireject
A modification of aireplay-ng from for enhanced packet injection testing.

I created this project due to the limitations of the existing aireplay-ng packet injection test functionality.  Using the packet injection test functionality of aireplay-ng enables you to test the ability for a wireless adaptor to perform packet injection, as well as its ability to both send and receive packets between the local client and remote access point.

Using this test mode has several limitations, including:

 * A fixed limit of only 30 packets sent to a remote AP for injection testing
 * A short timeout for sampling available nearby networks, resulting in only a small sample being tested
 * Inability to select a target BSSID for injection testing of a specific network
 * No channel hopping capability
 
By making the above options user-configurable, this project aims to provide a highly versatile packet injection test to provide real-time feedback without the requirement to authenticate with the remote device, enabling testing and adjustment of factors such as adaptor configuration and antenna positioning to achieve the most reliable two-way connection between a local client and remote AP.

Ideal for use for provisioning and testing of equipment over long-distance links.

Based on aircrack 1.2 rc4.

## Compiling

I'm unfamiliar with the usage of makefiles, so while this contains the relevant files, these have been copied across aircrack-ng 1.2-rc4 however I haven't modified them in any way - `make` will not work.  If anyone can help me out with this I'd be appreciative!

As a workaround, I've created two files: `/src/compile-x86` and `/src/compile-pi` - these may or may not work!  Tested under Ubuntu 10.04.4 LTS (old, I know - it was required for proper AWUS036H txpower support) and Raspbian Jessie 4.4.

Here's the install process under Raspbian Jessie:

```
wget https://github.com/cjastone/aireject/archive/master.zip -O aireject.zip
unzip aireject.zip
cd aireject-master/src
chmod +x compile-pi
./compile-pi
```

## Usage
To display usage, type `./aireject --help`
```
  Aireplay-ng 1.2 rc4 - (C) 2006-2015 Thomas d'Otreppe
  http://www.aircrack-ng.org

  aireject 0.1 modifications November 2016 by Chris Stone
  https://github.com/cjastone/aireject

  usage: aireject <options> <wlan interface>

  Options:

      -b bssid  : MAC address of target AP
      -c n      : channel on which to search for target, 0 to hop
      -r n      : number of requests to send per AP
      -t n      : timeout in seconds when waiting for AP beacons
      -B        : activates the bitrate test

  Miscellaneous options:

      --help              : Displays this usage screen
```

## Examples

```
sudo ./aireject wlan0
```
Run on wlan0 with default options.  Will hop all 2.4GHz channels for 20 seconds, then send 30 requests to each AP found.

```
sudo ./aireject wlan0 -c 6
```
Run on wlan0 channel 6 with all other default options.

```
sudo ./aireject wlan0 -c 12 -t 30
```
List all APs seen on channel 12 within 30 seconds with all other default options.

````
sudo ./aireject wlan0 -b a1:b2:c3:d4:e5:f6 -r 1000 -t 600
```
Hop channels for 600 seconds or until target BSSID a1:b2:c3:d4:e5:f6 found, then send 1000 requests to this target.

```
sudo ./aireject wlan0 -b a1:b2:c3:d4:e5:f6 -B
```
Perform a bitrate test against BSSID a1:b2:c3:d4:e5:f6.
