In order to run the programs, you should run "make all" in the
work directory of the project. The makefile will build 2 programs:
1) IPv4_Flood - Generator of TCP/IPv4 RST flood and UDP flood. The program functions as follows:
* The target IP-address for the flood attacks to be passed via command-line option -t whereas the default is 127.0.0.1;
* The target port to be passed via command-line option –p whereas the default is 443.
* Command-line option –r to switch from the default sending of RST flood to the UDP flood attack.
2) IPv6_Flood – Generator of UDPv6 flood. - This programs works as IPv4_Flood (Excluding the "-r" flag).

Example of a running session of the program:
1) Enter the terminal's direcory of the project.
2) run the command "make all".
3) choose a program to run "./IPv4_Flood" or "./IPv6_Flood".
*** You can use the flags as mentioned above.

In the Pcap direcory you can find Wireshark pcap files and a png pictures files of an example of a program run.