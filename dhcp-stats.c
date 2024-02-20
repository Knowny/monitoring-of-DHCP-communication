/**
 * @file dhcp-stats.c
 * @author Tomas Husar (xhusar11)
 * @brief dhcp-stats.c obtains statistics on network prefix utilization
 * @version 0.1
 * @date 2023-11-20
 * 
 * @copyright Copyright (c) 2023
 * 
 */

// standard C library headers
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <signal.h>

// networking and packet handling headers
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

// user interface headers
#include <ncurses.h>

// message logging headers
#include <syslog.h>

// STRUCTURE DEFINITIONS
/**
 * @brief structure Arguments contains:
 *  char *interface, 
 *  char *filename,
 *  char **subnets (array of ip-prefixes)
 *  int subnet_count (number of ip-prefixes)
 * 
 */
typedef struct{
    char *interface;
    char *filename;
    char **subnets;
    int subnet_count;
} Arguments;

/**
 * @brief structure defining IP_prefixes or ip addresses
 * ip addresses have no prefix and number of allocations
 * 
 * https://itecnote.com/tecnote/sockets-standard-safe-way-to-check-if-ip-address-is-in-range-subnet/
 * 
 */
typedef struct{
    int octets[4];
    int prefix;
    int num_of_allocations;
    uint32_t netip;     // network ip to compare with
    uint32_t netmask;   // network ip subnet mask
    uint32_t netstart;  // = (netip & netmask) -> first ip in subnet
    uint32_t netend;    // = (netstart | ~netmask) -> last ip in subnet
} IP_prefix;

/**
 * @brief structure defining DCHP packet
 * length of fields from: https://datatracker.ietf.org/doc/html/rfc2131
 * 
 */
typedef struct{
    u_char op;  
    u_char htype;
    u_char hlen;
    u_char hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    u_char chaddr[16];
    u_char sname[64];
    u_char file[128];
    u_char options[0];
} DHCP_header;

// GLOBAL VARIABLES
pcap_t* handle;     // struct that identifies the packet capture channel
int linkhdrlen;     // datalink header size
int packets;        // increments every time a packet is captured and processed

Arguments args;         // arguments from input
IP_prefix *prefixes;    // array of prefixes
WINDOW *my_win;         // UI Window

// FUNCTION DEFINITIONS
/**
 * @brief function parsing arguments from a command line
 * 
 * @param argc 
 * @param argv 
 * @return Arguments structure containing interface or filename, subnets and subnet_count
 */
Arguments arg_parse(int argc, char *argv[]) {

    Arguments args;
    args.interface = NULL;
    args.filename = NULL;
    args.subnets = NULL;
    args.subnet_count = 0;

    int opt;    // variable holds the result of getopt()
    while ((opt = getopt(argc, argv, "i:r:")) != -1 ) {
        switch (opt) {
        case 'i':
            args.interface = optarg;
            break;
        case 'r':
            args.filename = optarg;
            break;
        default:
            fprintf(stderr, "Usage:%s [-i <interface>] | [-r <filename>] <ip-prefix> [ip-prefix[...]]\n", argv[0]);
            exit(2);
        }
    }
    
    if ((args.interface == NULL && args.filename == NULL) || optind == argc) {
        fprintf(stderr, "Usage: %s [-i <interface>] | [-r <filename>] <ip-prefix> [ip-prefix[...]]\n", argv[0]);
        exit(2);
    }

    if (args.interface != NULL && args.filename != NULL) {
        fprintf(stderr, "Please provide either an interface or a filename, not both.\n");
        exit(2);
    }
    
    args.subnet_count = argc - optind;  // number of non-option arguments
    args.subnets = &argv[optind];       // assign the address of the first non-option argument (array of strings contains the subnets)

    return args;
}

/**
 * @brief function correctly frees the alloccated memory, and terminates the program
 * 
 * https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#libpcap-installation
 * 
 * @param signo 
 */
void stop_program(int signum){
    
    if (prefixes != NULL) {
        free(prefixes);        
    }

    if (handle != NULL) {
        pcap_close(handle);
    }

    if (my_win != NULL) {
        delwin(my_win);
        endwin();
    }

    closelog();     // close the syslog connection - safe even when the log is not opened

    exit(signum);   // exit
}

/**
 * @brief function checks, if the IP is valid: (0<=x<=255; x = octet)
 * 
 * @param prefixes 
 * @param i iterator
 * @return true when ip is valid
 * @return false when ip is invalid
 */
bool check_ip_range(IP_prefix *prefixes, int i){

    bool correct_ip_flag = true;

    for (int j = 0; j < 4; j++){
        if ((prefixes[i].octets[j] < 0) || (prefixes[i].octets[j] > 255)){
            
            correct_ip_flag = false;
        }
    }
    return correct_ip_flag;
}

/**
 * @brief function checks, if the IP is valid for the current prefix, and if the prefix is valid: (1<=y<=30; y = prefix)
 * 
 * @param prefixes 
 * @param i iterator
 * @return true if the ip and prefix are valid
 * @return false if the ip and prefix are invalid
 */
bool check_prefix_range(IP_prefix *prefixes, int i){

    bool correct_prefix_flag = true;

    if ((prefixes[i].prefix > 0) && (prefixes[i].prefix < 31)){
        int m = 32 - prefixes[i].prefix;
        int x;          //a modulo operand
        int result;     //result of modulo operations, if 0, IP is okay, otherwise IP is invalid
        
        if (m >= 0 && m <= 8){
            //number in last octet modulo 2 to the power of m must be 0
            x = (int)pow(2, m);
            result = prefixes[i].octets[3] % x;

            if(result != 0){
                correct_prefix_flag = false;
            }
        }
        if (m >= 9 && m <= 16){
            x = (int)pow(2, m-8);
            result = prefixes[i].octets[2] % x;
            // after prefix, all bits must be zeros
            if((result != 0) || (prefixes[i].octets[3] % 256 != 0)){
                correct_prefix_flag = false;
            }
        }
        if (m >= 17 && m <= 24){
            x = (int)pow(2, m-16);
            result = prefixes[i].octets[1] % x;
            // after prefix, all bits must be zeros
            if(result != 0 || (prefixes[i].octets[3] % 256 != 0) || (prefixes[i].octets[2] % 256 != 0)){
                correct_prefix_flag = false;
            }
        }
        if (m >= 25 && m <= 32){
            x = (int)pow(2, m-24);
            result = prefixes[i].octets[0] % x;
            // after prefix, all bits must be zeros
            if(result != 0 || (prefixes[i].octets[3] % 256 != 0) || (prefixes[i].octets[2] % 256 != 0) || (prefixes[i].octets[1] % 256)){
                correct_prefix_flag = false;
            }
        }
    } else {
        correct_prefix_flag = false;    // out of range 1-30
    }
    return correct_prefix_flag;
}

/**
 * @brief function returns netid from int octets
 * 
 * @param octets 
 * @return uint32_t 
 */
uint32_t get_netip(int octets[4]) {

    return ((uint32_t)octets[0] << 24) |
           ((uint32_t)octets[1] << 16) |
           ((uint32_t)octets[2] << 8) |
           (uint32_t)octets[3];
}

/**
 * @brief function returns netmask calculated from prefix
 * 
 * @param prefix int from 0 to 32
 * @return uint32_t netmask
 */
uint32_t get_netmask(int prefix) {

    uint32_t netmask = 0xFFFFFFFFU << (32 - prefix);
    return netmask;
}

/**
 * @brief function fills the IP_prefix array with ip prefixes
 * 
 * @return IP_prefix* ARRAY OF IP PREFIXES
 */
IP_prefix* init_IP_prefix_array(IP_prefix *prefixes, Arguments args){
        
    char *ip;       //x.x.x.x
    char *prefix;   //y

    for (int i = 0; i < args.subnet_count; i++) {

        ip = strtok(args.subnets[i], "/");  //x.x.x.x
        prefix = strtok(NULL, "/");         //y

        // fill the octets with integers
        if (ip != NULL && prefix != NULL) {
            prefixes[i].octets[0] = atoi(strtok(ip, "."));
            prefixes[i].octets[1] = atoi(strtok(NULL, "."));
            prefixes[i].octets[2] = atoi(strtok(NULL, "."));
            prefixes[i].octets[3] = atoi(strtok(NULL, "."));
            prefixes[i].prefix = atoi(prefix);
            prefixes[i].num_of_allocations = 0;
        } else {
            fprintf(stderr, "Invalid IP address\n");
            stop_program(2);
        }

        if (check_ip_range(prefixes, i) != true){
            fprintf(stderr, "Invalid IP address\n");
            stop_program(2);
        }

        if (check_prefix_range(prefixes, i) != true) {
            fprintf(stderr, "Invalid IP address\n");
            stop_program(2);
        }

        // set netip, netmask, netstart and netend
        prefixes[i].netip = get_netip(prefixes[i].octets);
        prefixes[i].netmask = get_netmask(prefixes[i].prefix);
        prefixes[i].netstart = (prefixes[i].netip & prefixes[i].netmask);
        prefixes[i].netend = (prefixes[i].netstart | ~prefixes[i].netmask);
        
    }
    return prefixes;
}

/**
 * @brief function checks, if the number of allocations exceeded the threshold, if they did, notify the admin
 * 
 * @param percent_before % before allocation
 * @param percent_after % after allocation
 * @param i iterator
 */
void check_prefix_allocation_threshold(IP_prefix *prefixes, float percent_before, float percent_after, int i){

    // check 50%
    if ((percent_before <= 50.0 ) && (percent_after > 50.0)) {

        syslog (LOG_NOTICE, "prefix %d.%d.%d.%d/%d exceeded 50%% of allocations.\n",
        prefixes[i].octets[0], prefixes[i].octets[1], 
        prefixes[i].octets[2], prefixes[i].octets[3], 
        prefixes[i].prefix);
    }

    // check 75%
    if ((percent_before <= 75.0 ) && (percent_after > 75.0)) {

        syslog (LOG_NOTICE, "prefix %d.%d.%d.%d/%d exceeded 75%% of allocations.\n",
        prefixes[i].octets[0], prefixes[i].octets[1], 
        prefixes[i].octets[2], prefixes[i].octets[3], 
        prefixes[i].prefix);
    }
    
    // check 90%
    if ((percent_before <= 90.0 ) && (percent_after > 90.0)) {

        syslog (LOG_NOTICE, "prefix %d.%d.%d.%d/%d exceeded 90%% of allocations.\n",
        prefixes[i].octets[0], prefixes[i].octets[1], 
        prefixes[i].octets[2], prefixes[i].octets[3], 
        prefixes[i].prefix);
    }
    
    // check 95%
    if ((percent_before <= 95.0 ) && (percent_after > 95.0)) {

        syslog (LOG_NOTICE, "prefix %d.%d.%d.%d/%d exceeded 95%% of allocations.\n",
        prefixes[i].octets[0], prefixes[i].octets[1], 
        prefixes[i].octets[2], prefixes[i].octets[3], 
        prefixes[i].prefix);
    }
}

/**
 * @brief function checks if ip adress is in any subnet, 
 * if server can give the client an ip adress, number of allocated ips increment for each neccesary subnet
 * 
 * https://itecnote.com/tecnote/sockets-standard-safe-way-to-check-if-ip-address-is-in-range-subnet/
 * 
 * @param prefixes an array of ip-prefixes
 * @param ip ip address from the DHCP packet
 * @param args arguments from the cmd line
 */
void increment_allocated_addresses(IP_prefix *prefixes, uint32_t ip, Arguments args){
    // * check all subnets
    for (int i = 0; i < args.subnet_count; i++){
        // * ip in range
        if ((ip > prefixes[i].netstart) && (ip < prefixes[i].netend)) {

            int max_allocations = (int)pow(2, (32-prefixes[i].prefix)) - 2;
            float percent_before = ((float)prefixes[i].num_of_allocations / (float)max_allocations) * 100;

            prefixes[i].num_of_allocations++;   //ip is on the same subnet -> increment number of allocations

            float percent_after = ((float)prefixes[i].num_of_allocations / (float)max_allocations) * 100;

            check_prefix_allocation_threshold(prefixes, percent_before, percent_after, i);                 
        }
    }
}

/**
 * @brief function prints statistics into the WINDOW
 * 
 * @param my_win window for printing
 * @param prefixes ip adresses to print
 * @param args arguments from the cmd line
 */
void print_stats(WINDOW *my_win, IP_prefix *prefixes, Arguments args){
        
    for (int i = 0; i < args.subnet_count; i++){
        
        int max_allocations = (int)pow(2, (32-prefixes[i].prefix)) - 2;

        float percentage = ((float)prefixes[i].num_of_allocations / (float)max_allocations) * 100;

        mvwprintw(my_win, 1+i, 0, "%d.%d.%d.%d/%d %d %d %0.2f%%", 
        prefixes[i].octets[0], prefixes[i].octets[1], 
        prefixes[i].octets[2], prefixes[i].octets[3], 
        prefixes[i].prefix, max_allocations,
        prefixes[i].num_of_allocations, percentage);
        
    }
    wrefresh(my_win);
}

/**
 * @brief packet handler is a callback function, invoked by libpcap whenever a packet is captured
 * 
 * https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#libpcap-installation
 * 
 * @param user pointer passed to pcap_loop()
 * @param pkthdr pointer to a struct containing info like timestamp and packet length
 * @param packet pointer to the captured packet data
 */
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {

    // pointers to Ethernet, IP and UDP ... musia byt const?
    const struct ether_header *eth_header;
    const struct iphdr *ip_header;
    const struct udphdr *udp_header;

    DHCP_header *dhcp_header;

    // Parse Ethernet header
    eth_header = (struct ether_header *)packet;

    // Check if the frame is IP, ntohs = network to host short
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Adjust the pointer to IP header
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));

        // Check if the packet is UDP
        if (ip_header->protocol == IPPROTO_UDP) {
            // Adjust the pointer to UDP header
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ihl * 4));    //multiply the header lenght by 4, because each word is 4 butes in size

            // Check if the UDP packet is DHCP (UDP port 67 or 68), htons = host to network short (big-endian)
            if (udp_header->source == htons(67) || udp_header->dest == htons(67) || udp_header->source == htons(68) || udp_header->dest == htons(68)) {

                // ptr to dhcp header
                dhcp_header = (DHCP_header *)(packet + sizeof(struct ether_header) + (ip_header->ihl * 4) + 8);    //length of udp is allways 8 bytes

                // moving pointer in packet
                packet += 14;                   //ether
                packet += ip_header->ihl *4;    //ip
                packet += 8;                    //udp
                packet += 240;                  //dhcp skip until options 236+4 (magic cookie)
                
                int i = 0;      //iterator
                int state = 1;  //first state in FSM
                bool ACK_flag = false;
                int len = 0;    //packet length

                // * simple Finite State Machine, 0x35 = DHCP MSG TYPE, 0x05 = DHCP ACK
                while (true) {
                    if (state == 1) {
                        if (packet[i] != 0x35) {
                            state = 2;
                        } else {
                            if (packet[i+2] == 0x05){
                                ACK_flag = true;
                            }
                            state = 3;  
                        }
                    } else if(state == 2){
                        len = packet[i];
                        i += len;
                        state = 1;
                    } else if(state == 3){
                        break;  //terminate the loop
                    }
                    i++;
                }

                // * ACK_flag == 1 -> check all subnets and increment num_of_allocation if neccessary
                if (ACK_flag){
                    increment_allocated_addresses(prefixes, ntohl(dhcp_header->yiaddr), args);
                    print_stats(my_win, prefixes, args);
                }
            }
        }
    }
}

// MAIN FUNCTION
int main(int argc, char *argv[]) {

    // * parse command line arguments into global args variable
    args = arg_parse(argc, argv);

    // * interruption handler
    signal(SIGINT, stop_program);
    signal(SIGTERM, stop_program);
    signal(SIGQUIT, stop_program);

    // * Dynamically allocate memory for a global array of IP_prefix structures
    prefixes = (IP_prefix *)malloc(args.subnet_count * sizeof(IP_prefix));

    if (prefixes == NULL) {
        fprintf(stderr,"Memory allocation failed\n");
        exit(1);
    }

    // * initialize the array of IP_prefix structures
    prefixes = init_IP_prefix_array(prefixes, args);

    // * set up syslog for logging
    setlogmask (LOG_UPTO (LOG_NOTICE)); // set the log mask to capture logs up to LOG_NOTICE level
    openlog ("exampleprog", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);   // open a connection with options

    // * initialize ncurses
    int height = 2 + args.subnet_count + 1; // 2 lines for the border, 1 for the text, others are ip-prefixes
    int width = 60;

    initscr();  // init screen
    refresh();  // draw the root window
    
    my_win = newwin(height, width, 0, 0);

    mvwprintw(my_win, 0, 0, "IP-Prefix Max-hosts Allocated addresses Utilization");
    wrefresh(my_win);

    // * print the stats before capturing packets
    print_stats(my_win, prefixes, args);

    // * Initialize pcap for interface or file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    bpf_u_int32 net, mask;   // variables for network number and network mask

    // * check if interface exists/is reachable
    if (pcap_lookupnet(args.interface, &net, &mask, errbuf) == -1 && (args.interface != NULL)) {
        fprintf(stderr, "Interface not reachable\n");
        stop_program(2);
    }

    // * open file for sniffing
    if (args.filename != NULL) {
        handle = pcap_open_offline(args.filename, errbuf);
    }
    
    // * open interface for sniffing
    if (args.interface != NULL) {
        handle = pcap_open_live(args.interface, BUFSIZ, 1, 1000, errbuf);
    }
    
    // * check if handle was created correctly
    if (handle == NULL) {
        fprintf(stderr, "Packet handle was not created correctly\n");
        stop_program(2);
    }

    // * start capturing packets 
    pcap_loop(handle, 0, packet_handler, NULL);

    getch();    // wait for character input to delete the window (reading from file)
    
    stop_program(0);
}