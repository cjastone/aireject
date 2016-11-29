# aireject
A modification of aireplay-ng for enhanced packet injection testing.

I created this project due to the limitations of the existing aireplay-ng packet injection test functionality.  Using the -9 (or --test) packet injection test under aireplay-ng enables you to test both the ability for a wireless adaptor to perform packet injection, as well as your ability to both send and receive packets between a local client and remote access point.

Using this test mode has several limitations, including:

 * A fixed limit of only 30 packets sent to a remote AP for injection testing
 * A short (~200ms) timeout for sampling available nearby networks, resulting in only a small sample being tested
 * Inability to select a target BSSID for injection testing of a specific network
 
By making the above options user-configurable, this project aims to provide a highly versatile packet injection test to provide real-time feedback, enabling testing and adjustment of factors such as adaptor configuration and antenna positioning to achieve the most reliable two-way connection between a local client and remote AP.
