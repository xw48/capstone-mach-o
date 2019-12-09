//
//  parse_mach.h
//  Capstone
//
//  Created by on 15/7/6.
//
//
#ifndef __Capstone__parse_mach__
#define __Capstone__parse_mach__

#include "m_loader.h"
#include "m_nlist.h"
#include "m_reloc.h"

#include <cstdio>
#include <cstdlib>
#include <queue>
#include <string>
#include <cstring>
#include <utility>
#include <algorithm>
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <unistd.h>
#include <fstream>
#include <tuple>
#include <cassert>
#include <stack>
#include "predefined.h"
#include "utils.h"
#include "json/json.h"
#include <codecvt>
#include <locale>
#include <cstddef>
#include <sstream>
#include <algorithm>

using namespace std;

extern "C"{
#include "../myinttypes.h"
#include "../include/capstone.h"
}

#define LIBRARY_THRESHOLD 500000

/*
 stored in __objc_data section
 */
typedef struct class_item{
    uint32_t meta_class;
    uint32_t super_class;
    uint32_t empty_cache;
    uint32_t zero;
    uint32_t class_data;
}class_item;

/*
 stored in __objc_const section
 */
typedef struct class_data{
    uint32_t padding[3];
    uint32_t ivar_layout;
    uint32_t class_name;
    uint32_t methods;
    uint32_t prots;
    uint32_t instance_variables;
    uint32_t zero;
    uint32_t properties;
}class_data;

typedef struct method_item{
    uint32_t method_name;
    uint32_t method_type;
    uint32_t method_addr_plus_one;
}method_item;

typedef struct methods_in_class{
    uint32_t padding;
    uint32_t method_count;
    method_item* methods;
}methods_in_class;

typedef struct cfstring_item{
    uint32_t unnamed1;
    uint32_t unnamed2;
    uint32_t cstring_ref;
    uint32_t unnamed3;
}cfstring_item;

typedef struct ivar_item{
    //address in __objc_ivar section
    uint32_t ivar_ref;
    //address in __objc_methname section, directs to string value
    uint32_t ivar_name;
    //address in __objc_methtype section
    uint32_t ivar_type;
    uint32_t padding[2];
}ivar_item;

typedef struct prop_item{
    uint32_t prop_name;
    uint32_t prop_type;
} prop_item;

typedef struct prot_item{
    uint32_t pad1;
    //prot_name appear in class_name section
    uint32_t name_ptr;
    //sub protocols in objc section
    uint32_t sub_prots;
    //method instances in const section
    uint32_t methods;
    uint32_t pad2[4];
}prot_item;

typedef enum{
    IVAR_REF,
    PROP_REF,
    SEL_REF,
    CLASS_REF,
    CFSTRING_REF,
    SYMBOL_STUB_REF,
    RELOC_BIND_TYPE,
    INTERNAL_IVAR_TYPE,
} REF_TYPE;

typedef uint32_t nl_symbol_item;

typedef struct method_block {
    string class_name;
    string method_name;
    uint32_t method_addr;
    
    //references of this method
    vector<pair<REF_TYPE, string>> base_ref;
    vector<struct method_block*> guess_invokes;
} method_block;

typedef uint32_t class_ref;

struct class_block {
    string class_name;
    class_ref super_class_addr;
    string super_class_name;
    //struct class_block* super_class;
    vector<method_block> class_or_instance_methods;
    //<name, type> pair
    vector<pair<string, string>> instance_variables;
    vector<pair<string, string>> props;
    set<string> protos;
    //TODO any other field (like prots, props) is not parsed here.
};

struct vc_struct {
    string vc_name;
    size_t signature;
    bool call_openurl;
    bool set_as_root_view;
    set<string> urls;
    vector<string> bag_of_words;
};

typedef struct class_block class_block;

class mach_desc{
public:
    string output_path;
    
    mach_desc(string path, string out_path): file_path(path), file_sha256(path), file_buffer(NULL), idx_data_seg(0), idx_dyld_info_cmd(0), idx_dysymtab_cmd(0), idx_linkedit_seg(0), idx_symtab_cmd(0), idx_text_seg(0), output_path(out_path){
        if(path.length() <= 0 || !mach_desc::is_mach_o_file(path)){
            return;
        }
        
        if (iOSConstants.size() <= 0 || LibraryClasses.size() <= 0) {
            localSetup();
        }
        
        string::size_type pos = path.find_last_of('/');
        if(pos != string::npos){
            file_sha256 = file_sha256.substr(pos+1);
        }
        
        if(this->fat_file_to_thin(path)){
            return;
        }
        
        this->read_file_to_memory();
        this->extract_mach_sects();
        this->extract_methods_and_refs();
        //this->dump_raw_strings();
        this->disasm();
        this->guess_invoke();
        //this->export_to_json();
        this->vc_analysis();
    }
    
    ~mach_desc(){
        this->release_file_buffer();
    }
    
    void release_file_buffer(){
        if(this->file_buffer != NULL){
            delete [] this->file_buffer;
            this->file_buffer = NULL;
            this->file_len = -1;
        }
    }
    
    static bool is_mach_o_file(const string& file_path);
    
    //below are interfaces for user
    void export_to_json();
    
private:
    //set up constants, iOS constants and Library list
    static set<string> iOSConstants;
    static map<size_t, int> LibraryClasses;
    
    string file_path;
    string file_sha256;
    
    size_t idx_mach_header;
    size_t idx_text_seg;
    size_t idx_data_seg;
    size_t idx_linkedit_seg;
    size_t idx_symtab_cmd;
    size_t idx_dysymtab_cmd;
    size_t idx_dyld_info_cmd;
    
    unsigned char* file_buffer;
    size_t file_len;
    vector<struct segment_command> segs;
    map<string, size_t> sections; //sections in __TEXT and __DATA segment and their indexes
    map<uint32_t, pair<REF_TYPE, string>> derived_refs;
    map<uint32_t, string> virtual_refs;
    map<string, class_block> class_blks;
    vector<string> class_def_order;
    
    //private methods
    int fat_file_to_thin(const string& file_path);
    void read_file_to_memory();
    int extract_mach_sects();
    int extract_methods_and_refs();
    void init_section_ptr();
    class_block* parse_class_item(class_item& cls_item);
    void extract_base_refs();
    void extract_virtual_refs();
    int disasm();
    void guess_invoke();
    void localSetup();
    
    void dump_raw_strings();
    
    /********************************************
                Customized Analysis
     ********************************************/
    int vc_analysis();
    
    //The following variables contain intermediate result!
    struct section *sec_classlist_ptr, *sec_cstring_ptr, *sec_bare_data_ptr, *sec_data_ptr, *sec_objc_const_ptr, *sec_classname_ptr, *sec_methname_ptr, *sec_methtype_ptr, *sec_selrefs_ptr, *sec_classrefs_ptr, *sec_superrefs_ptr, *sec_cfstring_ptr, *sec_text_ptr, *sec_ustring_ptr, *sec_nl_symbol_ptr, *sec_stub_ptr, *sec_data_const_ptr;
    cfstring_item* buffer_cfstring_ptr;
    
    unsigned char *buffer_cstring_ptr, *buffer_bare_data_ptr, *buffer_data_ptr, *buffer_objc_const_ptr, *buffer_classname_ptr, *buffer_methname_ptr, *buffer_methtype_ptr, *buffer_data_const_ptr;
    nl_symbol_item* buffer_nl_symbol_ptr;
    unsigned char *buffer_ustring_ptr;
    
    uint32_t* buffer_classlist_ptr, *buffer_selrefs_ptr, *buffer_classrefs_ptr, *buffer_superrefs_ptr;
    uint32_t classlist_count, selref_count, classref_count, superref_count;
    
    map<uint32_t, class_block*> addr_p2_class;
};

#endif
