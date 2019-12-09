//
//  utils.h
//  Capstone
//
//  Created by WangXueqiang on 10/15/15.
//
//

#ifndef Capstone_utils_h
#define Capstone_utils_h

#include <string>
#include <vector>
#include <set>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <functional>
using namespace std;

bool ends_with(string const & value, string const & ending);

typedef pair<string, size_t> PAIR;
struct {
    bool operator() (const PAIR& l, const PAIR& r){
        return l.second>r.second;
    }
} m_pair_cmp;

typedef pair<string, set<string> > PAIR_SET;
struct {
    bool operator() (const PAIR_SET& l, const PAIR_SET& r){
        return l.second.size() > r.second.size();
    }
} m_pair_set_cmp;

int max(int left, int right);

bool if_is_not_letter(char c);

void split(const string& s, char c,
           vector<string>& v);

set<string> interaction_set(const set<string>& left, const set<string>& right);

int left_is_subset(const set<string>& left, const set<string>& right);
set<string> measure_set_similarity(const set<string>& android_strings, const set<string>& ios_strings, const string& android_file = "");

size_t set_fingerprint(const set<string> contents);

#endif
