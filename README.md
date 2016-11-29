# aireject
A modification of aireplay-ng from for enhanced packet injection testing.

I created this project due to the limitations of the existing aireplay-ng packet injection test functionality.  Using the packet injection test functionality of aireplay-ng enables you to test the ability for a wireless adaptor to perform packet injection, as well as its ability to both send and receive packets between the local client and remote access point.

Using this test mode has several limitations, including:

 * A fixed limit of only 30 packets sent to a remote AP for injection testing
 * A short timeout for sampling available nearby networks, resulting in only a small sample being tested (with a hard limit of 20 APs)
 * Inability to select a target BSSID for injection testing of a specific network
 
By making the above options user-configurable, this project aims to provide a highly versatile packet injection test to provide real-time feedback, enabling testing and adjustment of factors such as adaptor configuration and antenna positioning to achieve the most reliable two-way connection between a local client and remote AP.

Ideal for use for provisioning and testing of equipment over long-distance links.

Based on aircrack 1.2 rc-4.
