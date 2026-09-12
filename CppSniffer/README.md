
# CppSniffer

A C++ program I created to target a machine and sniff packets being transferred from it. CppSniffer will also log captured packets to a text file named "packet_log.txt". For best results run with your network card in promiscuous mode!

To do:
- If the user provides an invalid network interface, return an error and prompt them to try again.
- If the user provides an invalid IP for BPF filter, return an error and prompt them to try again.
- Grab error code for network disconnect before running pcap_close()
- Add arguments to make BPF filter optional and/or have multiple target machines be fed into BPF filter.
- Make printing packet data to terminal faster
- Find a way to reduce disk space consumption of packet_log.txt

