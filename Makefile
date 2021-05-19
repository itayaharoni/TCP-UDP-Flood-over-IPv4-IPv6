OBJECT_IPV6=IPv6_Flood.c
OBJECT_IPV4=IPv4_Flood.c
GCC=gcc 
.PHONY=all clean
all: IPv4_Flood IPv6_Flood

IPv4_Flood: $(OBJECT_IPV4)
	$(GCC) -o IPv4_Flood $(OBJECT_IPV4)

IPv6_Flood: $(OBJECT_IPV6)
	$(GCC) -o IPv6_Flood $(OBJECT_IPV6)


clean:
	rm -f IPv4_Flood IPv6_Flood
