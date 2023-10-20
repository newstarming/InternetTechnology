#pragma once
#ifndef NPCAPPACKETHANDLER_H
#define NPCAPPACKETHANDLER_H

void packetHandler(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet);

#endif