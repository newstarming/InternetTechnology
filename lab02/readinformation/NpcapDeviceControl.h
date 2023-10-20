#pragma once
#ifndef NPCAPDEVICECONTROL_H
#define NPCAPDEVICECONTROL_H

#include <pcap.h>

pcap_t* OpenNpcapDevice(const char* deviceName);

#endif
