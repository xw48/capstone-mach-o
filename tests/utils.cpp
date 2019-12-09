//
//  utils.cpp
//  Capstone
//
//  Created by WangXueqiang on 10/15/15.
//
//

#include <stdio.h>
#include "utils.h"

bool ends_with(string const & value, string const & ending)
{
    if (ending.size() > value.size()) return false;
    return equal(ending.rbegin(), ending.rend(), value.rbegin());
}

inline int max(int left, int right){
    return left>right?left:right;
}

bool if_is_not_letter(char c){
    if((c >= 'a' && c <= 'z') || (c>= 'A' && c <= 'Z')){
        return false;
    }
    
    return true;
}

void split(const string& s, char c,
           vector<string>& v) {
    string::size_type i = 0;
    string::size_type j = s.find(c);
    
    while (j != string::npos) {
        v.push_back(s.substr(i, j-i));
        i = ++j;
        j = s.find(c, j);
        
        if (j == string::npos)
            v.push_back(s.substr(i, s.length()));
    }
}

set<string> interaction_set(const set<string>& left, const set<string>& right){
    set<string> ret_set;
    
    vector<string> left_vec;
    left_vec.insert(left_vec.begin(), left.begin(), left.end());
    sort(left_vec.begin(), left_vec.end());
    
    vector<string> right_vec;
    right_vec.insert(right_vec.begin(), right.begin(), right.end());
    sort(right_vec.begin(), right_vec.end());
    
    vector<string> ret_vec;
    set_intersection(left_vec.begin(), left_vec.end(), right_vec.begin(), right_vec.end(), std::back_inserter(ret_vec));
    
    ret_set.insert(ret_vec.begin(), ret_vec.end());
    
    return ret_set;
}

int left_is_subset(const set<string>& left, const set<string>& right){
    vector<string> left_vec;
    left_vec.insert(left_vec.begin(), left.begin(), left.end());
    sort(left_vec.begin(), left_vec.end());
    
    vector<string> right_vec;
    right_vec.insert(right_vec.begin(), right.begin(), right.end());
    sort(right_vec.begin(), right_vec.end());
    
    vector<string> ret_vec;
    set_intersection(left_vec.begin(), left_vec.end(), right_vec.begin(), right_vec.end(), std::back_inserter(ret_vec));
    
    if(ret_vec.size() >= left.size()){
        return 1;
    }else if(ret_vec.size() >= right.size()){
        return -1;
    }else{
        return 0;
    }
}

set<string> measure_set_similarity(const set<string>& android_strings, const set<string>& ios_strings, const string& android_file){
    set<string> common_strings;
    set<string> no_repeat_pair;
    
    string com_string(android_file);
    if(com_string.length() > 0){
        com_string.append("_comString");
    }else{
        com_string.append("/dev/null");
    }
    ofstream ofs_com_string(com_string, ofstream::app);
    
    for(set<string>::const_iterator iter_android_strings = android_strings.begin(); iter_android_strings != android_strings.end(); ++iter_android_strings){
        for(set<string>::const_iterator iter_ios_strings = ios_strings.begin(); iter_ios_strings != ios_strings.end(); ++iter_ios_strings){
            string ios_pure_item(*iter_ios_strings);
            string android_pure_item(*iter_android_strings);
            
            string::size_type http_len = string("https://").length();
            
            if((ios_pure_item.find("http:") != string::npos || ios_pure_item.find("https:") != string::npos) && (android_pure_item.find("http:") || android_pure_item.find("https:"))){
                if(ios_pure_item.length() <= (string("http://%@").length()+3) || android_pure_item.length() <= (string("http://%s").length()+3)){
                    continue;
                }
                string::size_type slas_pos_android = android_pure_item.find("//");
                string::size_type slas_pos_ios = ios_pure_item.find("//");
                if(slas_pos_android == string::npos || slas_pos_ios == string::npos){
                    continue;
                }
                
                string::size_type ios_pos = ios_pure_item.find("/", http_len);
                if(ios_pos != string::npos){
                    ios_pure_item = ios_pure_item.substr(ios_pure_item.find("//")+2, ios_pos-(ios_pure_item.find("//")+2));
                }
                
                string::size_type android_pos = android_pure_item.find("/", http_len);
                if(android_pos != string::npos){
                    android_pure_item = android_pure_item.substr(android_pure_item.find("//")+2, android_pos-(android_pure_item.find("//")+2));
                }
                
                if(!ios_pure_item.compare(android_pure_item)){
                    common_strings.insert(*iter_ios_strings);
                    ofs_com_string << "\"" << *iter_android_strings << "\"----\"" << *iter_ios_strings << "\"" << endl;
                    break;
                }
            }else{
                ios_pure_item.erase(std::remove_if(ios_pure_item.begin(), ios_pure_item.end(), if_is_not_letter), ios_pure_item.end());
                android_pure_item.erase(std::remove_if(android_pure_item.begin(), android_pure_item.end(), if_is_not_letter), android_pure_item.end());
                
                if(ios_pure_item.length() < 3 || android_pure_item.length() < 3){
                    continue;
                }
                if(ios_pure_item.length() > android_pure_item.length()){
                    if(ios_pure_item.find(android_pure_item) != string::npos){
                        if((float)(android_pure_item.length())/(float)(ios_pure_item.length()) >= 0.8){
                            if(no_repeat_pair.count(android_pure_item+"----"+ios_pure_item) <= 0){
                                no_repeat_pair.insert(android_pure_item+"----"+ios_pure_item);
                                ofs_com_string << "\"" << *iter_android_strings << "\"----\"" << *iter_ios_strings << "\"" << endl;
                                common_strings.insert(*iter_ios_strings);
                                break;
                            }
                        }
                    }
                }else{
                    if(android_pure_item.find(ios_pure_item) != string::npos){
                        string::size_type android_len = android_pure_item.length();
                        if(android_pure_item.find("javascript") != string::npos){
                            android_len -= string("javascript").length();
                        }
                        if((float)(ios_pure_item.length())/(float)(android_len) >= 0.8){
                            if(no_repeat_pair.count(android_pure_item+"----"+ios_pure_item) <= 0){
                                no_repeat_pair.insert(android_pure_item+"----"+ios_pure_item);
                                
                                ofs_com_string << "\"" << *iter_android_strings << "\"----\"" << *iter_ios_strings << "\"" << endl;
                                common_strings.insert(*iter_ios_strings);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    ofs_com_string.close();
    
    return common_strings;
}

size_t set_fingerprint(const set<string> contents) {
    stringstream ss;
    for (set<string>::const_iterator iter_contents = contents.begin(); iter_contents != contents.end(); ++iter_contents) {
        ss << *iter_contents << ",";
    }
    std::hash<std::string> str_hash;
    return str_hash(ss.str());
}
