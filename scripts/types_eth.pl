#!/usr/bin/perl
%ethernettypes = (
	0000 => "IEEE802.3 Length Field",
	0257 => "Experimental",
	0512 => "XEROX PUP (see 0A00)",
	0513 => "PUP Addr Trans (see 0A01)",
	1536 => "XEROX NS IDP",
	2048 => "Internet IP (IPv4)",
	2049 => "X.75 Internet",
	2050 => "NBS Internet",
	2051 => "ECMA Internet",
	2052 => "Chaosnet",
	2053 => "X.25 Level 3",
	2054 => "ARP",
	2055 => "XNS Compatability",
	2056 => "Frame Relay ARP",
	2076 => "Symbolics Private",
	2184 => "Xyplex",
	2304 => "Ungermann-Bass net debugr",
	2560 => "Xerox IEEE802.3 PUP",
	2561 => "PUP Addr Trans",
	2989 => "Banyan VINES",
	2990 => "VINES Loopback",
	2991 => "VINES Echo",
	4096 => "Berkeley Trailer nego",
	4097 => "Berkeley Trailer encap/IP",
	5632 => "Valid Systems",
	16962 => "PCS Basic Block Protocol",
	21000 => "BBN Simnet",
	24576 => "DEC Unassigned (Exp.)",
	24577 => "DEC MOP Dump/Load",
	24578 => "DEC MOP Remote Console",
	24579 => "DEC DECNET Phase IV Route",
	24580 => "DEC LAT",
	24581 => "DEC Diagnostic Protocol",
	24582 => "DEC Customer Protocol",
	24583 => "DEC LAVC, SCA",
	24584 => "DEC Unassigned",
	24586 => "3Com Corporation",
	25944 => "Trans Ether Bridging",
	25945 => "Raw Frame Relay",
	28672 => "Ungermann-Bass download",
	28674 => "Ungermann-Bass dia/loop",
	28704 => "LRT",
	28720 => "Proteon",
	28724 => "Cabletron",
	32771 => "Cronus VLN",
	32772 => "Cronus Direct",
	32773 => "HP Probe",
	32774 => "Nestar",
	32776 => "AT&T",
	32784 => "Excelan",
	32787 => "SGI diagnostics",
	32788 => "SGI network games",
	32789 => "SGI reserved",
	32790 => "SGI bounce server",
	32793 => "Apollo Domain",
	32815 => "Tymshare",
	32816 => "Tigan, Inc.",
	32821 => "Reverse ARP",
	32822 => "Aeonic Systems",
	32824 => "DEC LANBridge",
	32825 => "DEC Unassigned",
	32829 => " DEC Ethernet Encryption",
	32830 => "DEC Unassigned",
	32831 => " DEC LAN Traffic Monitor",
	32832 => "DEC Unassigned",
	32836 => "Planning Research Corp.",
	32838 => "AT&T",
	32839 => "AT&T",
	32841 => "ExperData",
	32859 => "Stanford V Kernel exp.",
	32860 => "Stanford V Kernel prod.",
	32861 => "Evans & Sutherland",
	32864 => "Little Machines",
	32866 => "Counterpoint Computers",
	32869 => "Univ. of Mass. @ Amherst",
	32870 => "Univ. of Mass. @ Amherst",
	32871 => "Veeco Integrated Auto.",
	32872 => "General Dynamics",
	32873 => "AT&T",
	32874 => "Autophon",
	32876 => "ComDesign",
	32877 => "Computgraphic Corp.",
	32878 => "Landmark Graphics Corp.",
	32890 => "Matra",
	32891 => "Dansk Data Elektronik",
	32892 => "Merit Internodal",
	32893 => "Vitalink Communications",
	32896 => "Vitalink TransLAN III",
	32897 => "Counterpoint Computers",
	32923 => "Appletalk",
	32924 => "Datability",
	32927 => "Spider Systems Ltd.",
	32931 => "Nixdorf Computers",
	32932 => "Siemens Gammasonics Inc.",
	32960 => "DCA Data Exchange Cluster",
	32964 => "Banyan Systems",
	32965 => "Banyan Systems",
	32966 => "Pacer Software",
	32967 => "Applitek Corporation",
	32968 => "Intergraph Corporation",
	32973 => "Harris Corporation",
	32975 => "Taylor Instrument",
	32979 => "Rosemount Corporation",
	32981 => "IBM SNA Service on Ether",
	32989 => "Varian Associates",
	32990 => "Integrated Solutions TRFS",
	32992 => "Allen-Bradley",
	32996 => "Datability",
	33010 => "Retix",
	33011 => "AppleTalk AARP (Kinetics)",
	33012 => "Kinetics",
	33015 => "Apollo Computer",
	33023 => "Wellfleet Communications",
	33031 => "Symbolics Private",
	33072 => "Hayes Microcomputers",
	33073 => "VG Laboratory Systems",
	33074 => "Bridge Communications",
	33079 => "Novell, Inc.",
	33081 => "KTI",
	33100 => "SNMP",
	34525 => "Internet Protocol (IPv6)",
	34543 => "ATOMIC",
	34667 => "TCP/IP Compression",
	34668 => "IP Autonomous Systems",
	34669 => "Secure Data",
	36864 => "Loopback",
	36865 => "3Com(Bridge) XNS Sys Mgmt",
	36866 => "3Com(Bridge) TCP-IP Sys",
	36867 => "3Com(Bridge) loop detect",
	65280 => "BBN VITAL-LanBridge cache",
	65535 => "Reserved",
);