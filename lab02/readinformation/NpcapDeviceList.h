#pragma once
#ifndef NPCAPDEVICELIST_H
#define NPCAPDEVICELIST_H

#include <vector>
#include <string>

struct NetworkDevice {
    std::string name;
    std::string description;
};

std::vector<NetworkDevice> GetNpcapDeviceList();

#endif
