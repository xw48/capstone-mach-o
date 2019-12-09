//
//  process_android_2_ios.cpp
//  Capstone
//
//  Created by WangXueqiang on 9/30/15.
//
//

#include "main.h"
#include <functional>
#include "utils.h"
#include <iostream>
#include <cstdlib>
#include <string>
using namespace std;

set<string> mach_desc::iOSConstants;
map<size_t, int> mach_desc::LibraryClasses;

inline void usage_info(const char* program){
    printf("USAGE: %s MACH_PATH OUTPUT_PATH\n", program);
}

int main(int argc, char** argv){
    if(argc < 3){
        usage_info(argv[0]);
        return -1;
    }
    
    mach_desc mach_file(argv[1], argv[2]);
    return 0;
}
