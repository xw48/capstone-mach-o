//
//  base64.h
//  Capstone
//
//  Created by WangXueqiang on 8/18/15.
//
//

#ifndef __Capstone__base64__
#define __Capstone__base64__

#include <string>

std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);

#endif /* defined(__Capstone__base64__) */