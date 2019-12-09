//
//  parse_mach.cpp
//  Capstone
//
//  Created by xw on 15/7/6.
//
//

#include "parse_mach.h"
#include "../cs_priv.h"

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <queue>
#include <string>
#include <cstring>
#include <utility>
#include <algorithm>
#include <set>
#include <map>
using namespace std;

#define switch_endian_32(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)&0xff0000)>>8)|(((x)&0xff000000)>>24))
#define G_TYPE_ARCH_ARM 0x0c000000

static uintptr_t read_uleb128(const uint8_t*& p, const uint8_t* end)
{
    uint64_t result = 0;
    int		 bit = 0;
    do {
        if (p == end)
            cout << "malformed uleb128" << endl;
        
        uint64_t slice = *p & 0x7f;
        
        if (bit > 63)
            cout << "uleb128 too big" << endl;
        else {
            result |= (slice << bit);
            bit += 7;
        }
    }while (*p++ & 0x80);
    return result;
}


static intptr_t read_sleb128(const uint8_t*& p, const uint8_t* end)
{
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        if (p == end)
            cout << "malformed sleb128" << endl;
        byte = *p++;
        result |= (((int64_t)(byte & 0x7f)) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if ( (byte & 0x40) != 0 )
        result |= (-1LL) << bit;
    return result;
}


bool mach_desc::is_mach_o_file(const string& file_path){
    bool is_mach_o = false;
    if(file_path.length() <= 0){
        return false;
    }
    
    ifstream ifile(file_path, ios::in);
    uint32_t magic_number;
    ifile.read(reinterpret_cast<char*>(&magic_number), sizeof(magic_number));
    
    if(ifile){
        if(!(magic_number^0xfeedface) || !(magic_number^0xcafebabe) || !(magic_number^0xcefaedfe) || !(magic_number^0xbebafeca))
            is_mach_o = true;
    }
    
    ifile.close();
    return is_mach_o;
}

/*
 on fat binaries, extract code for single architecture and replace original file
 */
int mach_desc::fat_file_to_thin(const string& file_path){
    ifstream ifs(file_path, ios::in);
    
    struct fat_header header;
    ifs.read(reinterpret_cast<char*>(&header), sizeof(header));
    
    if(!ifs){
        ifs.close();
        return -1;
    }
    
    uint32_t nfat = switch_endian_32(header.nfat_arch) & 0xff;
    if(nfat > 0){
        struct fat_arch* archs = new struct fat_arch[nfat];
        
        if(archs == NULL){
            ifs.close();
            return -1;
        }
        
        ifs.read(reinterpret_cast<char*>(archs), sizeof(struct fat_arch)*nfat);
        if(!ifs){
            cout << "error reading file" << file_path << endl;
            ifs.close();
            delete [] archs;
            return -1;
        }
        
        for(int idx = 0; idx < nfat; idx++){
            cpu_type_t type = archs[idx].cputype;
            if(type == G_TYPE_ARCH_ARM){
                cpu_subtype_t subtype = switch_endian_32(archs[idx].cpusubtype);
                uint32_t offset = switch_endian_32(archs[idx].offset);
                uint32_t size = switch_endian_32(archs[idx].size);
                
                ifs.seekg(offset, ios_base::beg);
                char* buffer = new char[size];
                if(buffer == NULL){
                    ifs.close();
                    delete [] archs;
                    return -1;
                }
                ifs.read(buffer, size);
                
                if(!ifs){
                    ifs.close();
                    delete [] archs;
                    return -1;
                }
                
                ifs.close();
                
                cout << "extracting thin mach-o for cpu " << subtype << endl;
                ofstream ofs(file_path, ios::trunc);
                ofs.write(buffer, size);
                ofs.close();
                break;
            }
        }
        delete [] archs;
    }else{
        ifs.close();
    }
    return 0;
}

void mach_desc::read_file_to_memory(){
    if(this->file_path.length() <= 0){
        cout << "file path not initialized!" << endl;
        this->file_len = -1;
        return;
    }
    
    FILE* fp = fopen(this->file_path.c_str(), "r");
    if(fp == NULL){
        cout << "open file failed!" << endl;
        this->file_len = -1;
        return;
    }
    
    fseek(fp, 0, SEEK_END);
    this->file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if(this->file_len <= 0){
        cout << "fseek file failed!" << endl;
        this->file_len = -1;
        fclose(fp);
        return;
    }
    
    this->file_buffer = new unsigned char[this->file_len];
    if(this->file_buffer == NULL){
        cout << "allocate memory failed!" << endl;
        this->file_len = -1;
        fclose(fp);
        return;
    }
    
    size_t read_len = fread(this->file_buffer, sizeof(unsigned char), this->file_len, fp);
    if(read_len < this->file_len){
        cout << "read file failed!" << endl;
        delete [] this->file_buffer;
        this->file_len = -1;
        fclose(fp);
        return;
    }
    fclose(fp);
}

int mach_desc::extract_mach_sects(){
    //read file from file_path
    if(this->file_len <= 0){
        cout << "file path not initialized!" << endl;
        return -1;
    }
    
    size_t file_cursor = 0;
    this->idx_mach_header = file_cursor;
   
    // in case there is no __PAGEZERO segment
    file_cursor += (sizeof(struct mach_header)); 
    //neglect __PAGEZERO segment
    //file_cursor += (sizeof(struct mach_header)+sizeof(struct segment_command));
    
    if(file_cursor >= this->file_len){
        cout << "file cursor out of bound before __TEXT!" << endl;
        return -1;
    }
    
    this->idx_text_seg = file_cursor;
    struct segment_command* text_seg = reinterpret_cast<struct segment_command*>(this->file_buffer+this->idx_text_seg);
    file_cursor += sizeof(struct segment_command);
    if(text_seg->nsects > 0){
        for(int idx = 0; (idx < text_seg->nsects) && (file_cursor < this->file_len); idx++){
            struct section* sect = reinterpret_cast<struct section*>(this->file_buffer+file_cursor);
            string sectname(sect->sectname);
            
            size_t pos__TEXT = sectname.find("__TEXT");
            if(pos__TEXT != string::npos){
                sectname = sectname.substr(0, pos__TEXT);
            }
            cout << "inserted " << sectname << endl;
            this->sections.insert(make_pair(sectname, file_cursor));
            file_cursor += sizeof(struct section);
        }
    }
    
    if(file_cursor >= this->file_len){
        cout << "file cursor out of bound before __DATA" << endl;
        return -1;
    }
    this->idx_data_seg = file_cursor;
    struct segment_command* data_seg = reinterpret_cast<struct segment_command*>(this->file_buffer+this->idx_data_seg);
    file_cursor += sizeof(struct segment_command);
    if(data_seg->nsects > 0){
        for(int idx = 0; idx < data_seg->nsects && file_cursor < this->file_len; idx++){
            struct section* sect = reinterpret_cast<struct section*>(this->file_buffer+file_cursor);
            string sectname(sect->sectname);
            
            size_t pos__DATA = sectname.find("__DATA");
            if(pos__DATA != string::npos){
                sectname = sectname.substr(0, pos__DATA);
            }
            cout << "inserted " << sectname << endl;
            this->sections.insert(make_pair(sectname, file_cursor));
            file_cursor += sizeof(struct section);
        }
    }
    
    struct load_command* load_cmd;
    int cmds_found = 0;
    
    struct mach_header* header = reinterpret_cast<struct mach_header*>(this->file_buffer + this->idx_mach_header);
    for(int idx = 3; (idx < header->ncmds) && (cmds_found < 4) && (file_cursor < this->file_len); idx++){
        load_cmd = reinterpret_cast<struct load_command*>(this->file_buffer + file_cursor);
        switch(load_cmd->cmd){
            case LC_SYMTAB:{
                this->idx_symtab_cmd = file_cursor;
                cmds_found++;
            }
                break;
            case LC_DYSYMTAB:{
                this->idx_dysymtab_cmd = file_cursor;
                cmds_found++;
            }
                break;
            case LC_SEGMENT:{
                struct segment_command* seg = reinterpret_cast<struct segment_command*>(this->file_buffer + file_cursor);
                if(!strcmp("__LINKEDIT", seg->segname)){
                    this->idx_linkedit_seg = file_cursor;
                    cmds_found++;
                }
            }
                break;
            case LC_DYLD_INFO_ONLY:{
                this->idx_dyld_info_cmd = file_cursor;
                cmds_found++;
            }
                break;
            default:
                break;
                
        }
        file_cursor += load_cmd->cmdsize;
    }
    
    return 0;
}

int mach_desc::extract_methods_and_refs(){
    if(this->file_len <= 0){
        cout << "file not initialized!" << endl;
        return -1;
    }
    
    map<string, size_t>::const_iterator it = this->sections.find("__objc_classlist");
    if(it == this->sections.end()){
        cout << "__objc_classlist not found" << endl;
        return -1;
    }
    struct section* sec_classlist_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    uint32_t* buffer_classlist_sec = reinterpret_cast<uint32_t*>(this->file_buffer + sec_classlist_ptr->offset);
    if(buffer_classlist_sec >= (uint32_t*)(this->file_buffer+this->file_len)){
        cout << "buffer_classlist_sec out of range" << endl;
        return -1;
    }
    uint32_t classlist_count = sec_classlist_ptr->size/(sizeof(uint32_t)/sizeof(unsigned char));
    
    it = this->sections.find("__cstring");
    if(it == this->sections.end()){
        cout << "__cstring not found" << endl;
        return -1;
    }
    struct section* sec_cstring_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    unsigned char* buffer_cstring_ptr = this->file_buffer+sec_cstring_ptr->offset;
    if(buffer_cstring_ptr >= (this->file_buffer+this->file_len)){
        cout << "buffer_cstring_ptr out of range" << endl;
        return -1;
    }
    
    it = this->sections.find("__data");
    if(it == this->sections.end()){
        cout << "__data not found" << endl;
        return -1;
    }
    struct section* sec_bare_data_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    unsigned char* buffer_bare_data_ptr = this->file_buffer+sec_bare_data_ptr->offset;
    if(buffer_bare_data_ptr >= (this->file_buffer+this->file_len)){
        cout << "buffer_bare_data_ptr out of range" << endl;
        return -1;
    }
    
    it = this->sections.find("__objc_data");
    if(it == this->sections.end()){
        cout << "__objc_data not found" << endl;
        return -1;
    }
    struct section* sec_data_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    unsigned char* buffer_data_sec = this->file_buffer + sec_data_ptr->offset;
    if(buffer_data_sec >= (this->file_buffer+this->file_len)){
        cout << "buffer_data_sec out of range" << endl;
        return -1;
    }
    
    it = this->sections.find("__objc_const");
    if(it == this->sections.end()){
        cout << "__objc_const not found" << endl;
        return -1;
    }
    struct section* sec_const_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    unsigned char* buffer_const_sec = this->file_buffer + sec_const_ptr->offset;
    if(buffer_const_sec >= (this->file_buffer+this->file_len)){
        cout << "buffer_const_sec out of range" << endl;
        return -1;
    }
    
    it = this->sections.find("__objc_classname");
    struct section* sec_classname_ptr;
    unsigned char* buffer_classname_sec;
    if(it == this->sections.end()){
        cout << "__objc_classname not found, use cstring" << endl;
        sec_classname_ptr = sec_cstring_ptr;
        buffer_classname_sec = buffer_cstring_ptr;
    }else{
        sec_classname_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        buffer_classname_sec = this->file_buffer + sec_classname_ptr->offset;
        if(buffer_classname_sec >= (this->file_buffer+this->file_len)){
            cout << "buffer_classname_sec out of range" << endl;
            return -1;
        }
    }
    
    it = this->sections.find("__objc_methname");
    struct section* sec_methname_ptr;
    unsigned char* buffer_methname_sec;
    
    if(it == this->sections.end()){
        cout << "__objc_methname not found, use cstring" << endl;
        sec_methname_ptr = sec_cstring_ptr;
        buffer_methname_sec = buffer_cstring_ptr;
    }else{
        sec_methname_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        buffer_methname_sec = this->file_buffer + sec_methname_ptr->offset;
        if(buffer_methname_sec >= (this->file_buffer+this->file_len)){
            cout << "buffer_methname_sec out of range" << endl;
            return -1;
        }
    }
    
    it = this->sections.find("__objc_methtype");
    struct section* sec_methtype_ptr;
    unsigned char* buffer_methtype_sec;
    
    if(it == this->sections.end()){
        cout << "__objc_methtype not found, use cstring" << endl;
        sec_methtype_ptr = sec_cstring_ptr;
        buffer_methtype_sec = buffer_cstring_ptr;
    }else{
        sec_methtype_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        buffer_methtype_sec = this->file_buffer + sec_methtype_ptr->offset;
        if(buffer_methtype_sec >= (this->file_buffer+this->file_len)){
            cout << "buffer_methtype_sec out of range" << endl;
            return -1;
        }
    }
    
    it = this->sections.find("__objc_selrefs");
    if(it == this->sections.end()){
        cout << "__objc_selrefs not found" << endl;
        return -1;
    }
    struct section* sec_selrefs_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    uint32_t* buffer_selrefs_ptr = reinterpret_cast<uint32_t*>(this->file_buffer + sec_selrefs_ptr->offset);
    if(buffer_selrefs_ptr >= (uint32_t*)(this->file_buffer+this->file_len)){
        cout << "buffer_selrefs_ptr out of range" << endl;
        return -1;
    }
    
    uint32_t selref_count = sec_selrefs_ptr->size/(sizeof(uint32_t)/sizeof(unsigned char));
    
    it = this->sections.find("__objc_classrefs");
    if(it == this->sections.end()){
        cout << "__objc_classrefs not found" << endl;
        return -1;
    }
    struct section* sec_classrefs_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    uint32_t* buffer_classrefs_ptr = reinterpret_cast<uint32_t*>(this->file_buffer+sec_classrefs_ptr->offset);
    if(buffer_classrefs_ptr >= (uint32_t*)(this->file_buffer+this->file_len)){
        cout << "buffer_classrefs_ptr out of range" << endl;
        return -1;
    }
    uint32_t classref_count = sec_classrefs_ptr->size/(sizeof(uint32_t)/sizeof(unsigned char));
    
    it = this->sections.find("__objc_superrefs");
    if(it == this->sections.end()){
        cout << "__objc_superrefs not found" << endl;
        return -1;
    }
    struct section* sec_superrefs_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    uint32_t* buffer_superrefs_ptr = reinterpret_cast<uint32_t*>(this->file_buffer+sec_superrefs_ptr->offset);
    if(buffer_superrefs_ptr >= (uint32_t*)(this->file_buffer+this->file_len)){
        cout << "buffer_superrefs_ptr out of range" << endl;
        return -1;
    }
    uint32_t superref_count = sec_superrefs_ptr->size/(sizeof(uint32_t)/sizeof(unsigned char));
    
    it = this->sections.find("__cfstring");
    if(it == this->sections.end()){
        cout << "__cfstring not found" << endl;
        return -1;
    }
    struct section* sec_cfstring_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    cfstring_item* buffer_cfstring_ptr = reinterpret_cast<cfstring_item*>(this->file_buffer+sec_cfstring_ptr->offset);
    
    /*direct to class data in __objc_data section, used to build class references.*/
    map<uint32_t, string> cls_data_addr2clsname;
    
    map<string, uint32_t> class_super_addr;
    
    /*
     There are two ways to extract class defs in mach-o file
     1) find entries of each class from classlist segment (class list may not be complete)
     2) enumerate obj_data segment for each class structures (complete, take care of segmentation fault!)
     */
    
    /*
     1) begin extracting defined methods
     */
    /*
    for(int idx = 0; idx < classlist_count; idx++){
        uint32_t class_ref = buffer_classlist_sec[idx];
        if(class_ref < sec_data_ptr->addr || class_ref > (sec_data_ptr->addr + sec_data_ptr->size)){
            continue;
        }
        class_item cls_item;
        memcpy(&cls_item, buffer_data_sec+(class_ref-sec_data_ptr->addr), sizeof(class_item));
        
        if(cls_item.class_data < sec_const_ptr->addr || cls_item.class_data > (sec_const_ptr->addr + sec_const_ptr->size)){
            continue;
        }
        
        class_data cls_data;
        memcpy(&cls_data, buffer_const_sec+(cls_item.class_data - sec_const_ptr->addr), sizeof(class_data));
        
        if(cls_data.class_name < sec_classname_ptr->addr || cls_data.class_name > (sec_classname_ptr->addr + sec_classname_ptr->size)){
            continue;
        }
        
        string cls_name(reinterpret_cast<const char*>(buffer_classname_sec + (cls_data.class_name - sec_classname_ptr->addr)));
        cls_data_addr2clsname.insert(make_pair(class_ref, cls_name));
        
        if(cls_item.super_class != 0){
            class_super_addr.insert(make_pair(cls_name, cls_item.super_class));
        }
        
        if(cls_data.methods != 0){
            methods_in_class methods_in_cls;
            memcpy(&methods_in_cls, buffer_const_sec+(cls_data.methods - sec_const_ptr->addr), sizeof(uint32_t)*2);
            if(methods_in_cls.method_count > 0){
                methods_in_cls.methods = new method_item[methods_in_cls.method_count];
                if(methods_in_cls.methods == NULL){
                    return -1;
                }
                
                memcpy(methods_in_cls.methods, buffer_const_sec+(cls_data.methods - sec_const_ptr->addr)+sizeof(uint32_t)*2, methods_in_cls.method_count*sizeof(method_item));
                
                for(int idx = 0; idx < methods_in_cls.method_count; idx++){
                    method_desc meth_desc;
                    meth_desc.class_name.append(cls_name);
                    meth_desc.method_addr = (methods_in_cls.methods[idx].method_addr_plus_one/sizeof(uint32_t))*sizeof(uint32_t);
                    meth_desc.event = NON_EVENT;
                    meth_desc.upper_caller = "";
                    
                    uint32_t meth_name_idx = methods_in_cls.methods[idx].method_name - sec_methname_ptr->addr;
                    
                    if(meth_name_idx > 0 && meth_name_idx < sec_methname_ptr->size){
                        meth_desc.method_name.append(reinterpret_cast<const char*>(buffer_methname_sec + meth_name_idx));
                        methods_addr2desc.insert(make_pair(meth_desc.method_addr, meth_desc));
                    }
                }
                delete [] methods_in_cls.methods;
            }
        }
        
        queue<uint32_t> proto_queue;
        proto_queue.push(cls_data.prots);
        
        while(!proto_queue.empty()){
            uint32_t cur_prot = proto_queue.front();
            proto_queue.pop();
            
            if(cur_prot == 0){
                continue;
            }
            
            uint32_t prot_cnt;
            memcpy(&prot_cnt, buffer_const_sec+(cur_prot - sec_const_ptr->addr), sizeof(uint32_t));
            if(prot_cnt > 0){
                uint32_t* prot_list = new uint32_t[prot_cnt];
                if(prot_list == NULL){
                    return -1;
                }
                memcpy(prot_list, buffer_const_sec+(cur_prot - sec_const_ptr->addr)+sizeof(uint32_t), prot_cnt*sizeof(uint32_t));
                
                for(int idx = 0; idx < prot_cnt; ++idx){
                    if(prot_list[idx] >= sec_bare_data_ptr->addr && prot_list[idx] < (sec_bare_data_ptr->addr+sec_bare_data_ptr->size)){
                        prot_item prot_struct;
                        memcpy(&prot_struct, buffer_bare_data_ptr+(prot_list[idx]-sec_bare_data_ptr->addr), sizeof(prot_item));
                        
                        if(prot_struct.name_ptr >= sec_classname_ptr->addr && prot_struct.name_ptr < (sec_classname_ptr->addr+sec_classname_ptr->size)){
                            string prot_name((char*)(buffer_classname_sec+(prot_struct.name_ptr-sec_classname_ptr->addr)));
                            
                            map<string, set<string>>::iterator iter_prots = this->class_prots.find(cls_name);
                            if(iter_prots == this->class_prots.end()){
                                set<string> prots;
                                prots.insert(prot_name);
                                this->class_prots.insert(make_pair(cls_name, prots));
                            }else{
                                iter_prots->second.insert(prot_name);
                            }
                            
                            map<string, set<string>>::iterator iter_delegates = this->delegates_implementations.find(prot_name);
                            if(iter_delegates == this->delegates_implementations.end()){
                                set<string> implements;
                                implements.insert(cls_name);
                                this->delegates_implementations.insert(make_pair("<" + prot_name +">", implements));
                            }else{
                                iter_delegates->second.insert(cls_name);
                            }
                        }
                        
                        if(prot_struct.sub_prots > 0){
                            proto_queue.push(prot_struct.sub_prots);
                        }
                    }
                }
                delete [] prot_list;
            }
        }
        
        if(cls_data.instance != 0){
            uint32_t ivar_size_and_count[2];
            memcpy(ivar_size_and_count, buffer_const_sec + cls_data.instance - sec_const_ptr->addr, 2*sizeof(uint32_t));
            
            if(ivar_size_and_count[0] == sizeof(ivar_item) && ivar_size_and_count[1] > 0){
                ivar_item* ivar_items = new ivar_item[ivar_size_and_count[1]];
                if(ivar_items == NULL){
                    return -1;
                }
                
                memcpy(ivar_items, buffer_const_sec + cls_data.instance - sec_const_ptr->addr + 2*sizeof(uint32_t), ivar_size_and_count[1]*sizeof(ivar_item));
                
                for(int idx = 0; idx < ivar_size_and_count[1]; idx++){
                     //log ivar as AdMoGoInterstitial.configKey(@"NSString")
                    if(ivar_items[idx].ivar_name < sec_methname_ptr->addr || ivar_items[idx].ivar_type < sec_methtype_ptr->addr){
                        continue;
                    }
                    string ivar_full(cls_name);
                    ivar_full.append(".");
                    const char* sel_name_ptr = reinterpret_cast<const char*>(buffer_methname_sec + (ivar_items[idx].ivar_name-sec_methname_ptr->addr));
                    const char* file_boundary = reinterpret_cast<const char*>(this->file_buffer+this->file_len);
                    
                    if (sel_name_ptr >= file_boundary) {
                        continue;
                    }
                    
                    ivar_full.append(sel_name_ptr);
                    ivar_full.append("(");
                    ivar_full.append(reinterpret_cast<const char*>(buffer_methtype_sec + (ivar_items[idx].ivar_type-sec_methtype_ptr->addr)));
                    ivar_full.append(")");
                    this->references_map.insert(make_pair(ivar_items[idx].ivar_ref, pair<ref_type, string>(IVAR_FULL_REF, ivar_full)));
                }
                
                delete[] ivar_items;
            }
        }
        
        if(cls_item.meta_class < sec_data_ptr->addr || cls_item.meta_class > (sec_data_ptr->addr + sec_data_ptr->size)){
            continue;
        }
        
        class_item cls_meta_item;
        memcpy(&cls_meta_item, buffer_data_sec+(cls_item.meta_class-sec_data_ptr->addr), sizeof(class_item));
        if(cls_meta_item.class_data < sec_const_ptr->addr || cls_meta_item.class_data > (sec_const_ptr->addr + sec_const_ptr->size)){
            continue;
        }
        
        class_data cls_meta_data;
        memcpy(&cls_meta_data, buffer_const_sec+(cls_meta_item.class_data - sec_const_ptr->addr), sizeof(class_data));
        if(cls_meta_data.class_name < sec_classname_ptr->addr || cls_meta_data.class_name > (sec_classname_ptr->addr + sec_classname_ptr->size)){
            continue;
        }
        
        if(cls_meta_data.methods != 0){
            methods_in_class methods_meta_in_cls;
            memcpy(&methods_meta_in_cls, buffer_const_sec+(cls_meta_data.methods - sec_const_ptr->addr), sizeof(uint32_t)*2);
            
            if(methods_meta_in_cls.method_count > 0){
                methods_meta_in_cls.methods = new method_item[methods_meta_in_cls.method_count];
                if(methods_meta_in_cls.methods == NULL){
                    return -1;
                }
                
                memcpy(methods_meta_in_cls.methods, buffer_const_sec+(cls_meta_data.methods - sec_const_ptr->addr)+sizeof(uint32_t)*2, methods_meta_in_cls.method_count*sizeof(method_item));
                
                for(int idx = 0; idx < methods_meta_in_cls.method_count; idx++){
                    method_desc meth_desc;
                    meth_desc.class_name.append(cls_name);
                    meth_desc.method_addr = (methods_meta_in_cls.methods[idx].method_addr_plus_one/sizeof(uint32_t)*sizeof(uint32_t));
                    meth_desc.event = NON_EVENT;
                    meth_desc.upper_caller = "";
                    uint32_t meth_name_idx = methods_meta_in_cls.methods[idx].method_name - sec_methname_ptr->addr;
                    if(meth_name_idx > 0 && meth_name_idx < sec_methname_ptr->size){
                        meth_desc.method_name.append(reinterpret_cast<const char*>(buffer_methname_sec + meth_name_idx));
                        methods_addr2desc.insert(make_pair(meth_desc.method_addr, meth_desc));
                    }
                }
                delete [] methods_meta_in_cls.methods;
            }
        }
    }
     */
    
    /*
     enumerate obj_data segment for class defs
     */
    
    unsigned char* class_data_begin = buffer_data_sec;
    unsigned char* class_data_end = buffer_data_sec + sec_data_ptr->size;
    unsigned char* class_data_idx = class_data_begin;
    
    while (class_data_idx + sizeof(class_item) < class_data_end ) {
        long class_ref = sec_data_ptr->addr + class_data_idx - class_data_begin;
        
        class_item cls_item;
        memcpy(&cls_item, class_data_idx, sizeof(class_item));
        class_data_idx += sizeof(class_item);
        
        if (cls_item.meta_class < sec_data_ptr->addr || cls_item.meta_class > (sec_data_ptr->addr + sec_data_ptr->size)) {
            continue;
        }
        
        if(cls_item.class_data < sec_const_ptr->addr || cls_item.class_data > (sec_const_ptr->addr + sec_const_ptr->size)){
            continue;
        }
        
        class_data cls_data;
        memcpy(&cls_data, buffer_const_sec+(cls_item.class_data - sec_const_ptr->addr), sizeof(class_data));
        
        if(cls_data.class_name < sec_classname_ptr->addr || cls_data.class_name > (sec_classname_ptr->addr + sec_classname_ptr->size)){
            continue;
        }
        
        string cls_name(reinterpret_cast<const char*>(buffer_classname_sec + (cls_data.class_name - sec_classname_ptr->addr)));
        cls_data_addr2clsname.insert(make_pair(class_ref, cls_name));
        
        if(cls_item.super_class != 0){
            class_super_addr.insert(make_pair(cls_name, cls_item.super_class));
        }
        
        if(cls_data.methods != 0){
            methods_in_class methods_in_cls;
            memcpy(&methods_in_cls, buffer_const_sec+(cls_data.methods - sec_const_ptr->addr), sizeof(uint32_t)*2);
            if(methods_in_cls.method_count > 0){
                methods_in_cls.methods = new method_item[methods_in_cls.method_count];
                if(methods_in_cls.methods == NULL){
                    return -1;
                }
                
                memcpy(methods_in_cls.methods, buffer_const_sec+(cls_data.methods - sec_const_ptr->addr)+sizeof(uint32_t)*2, methods_in_cls.method_count*sizeof(method_item));
                
                for(int idx = 0; idx < methods_in_cls.method_count; idx++){
                    method_desc meth_desc;
                    meth_desc.class_name.append(cls_name);
                    meth_desc.method_addr = (methods_in_cls.methods[idx].method_addr_plus_one/sizeof(uint32_t))*sizeof(uint32_t);
                    meth_desc.event = NON_EVENT;
                    meth_desc.upper_caller = "";
                    
                    uint32_t meth_name_idx = methods_in_cls.methods[idx].method_name - sec_methname_ptr->addr;
                    
                    if(meth_name_idx > 0 && meth_name_idx < sec_methname_ptr->size){
                        meth_desc.method_name.append(reinterpret_cast<const char*>(buffer_methname_sec + meth_name_idx));
                        methods_addr2desc.insert(make_pair(meth_desc.method_addr, meth_desc));
                    }
                }
                delete [] methods_in_cls.methods;
            }
        }
        
        queue<uint32_t> proto_queue;
        proto_queue.push(cls_data.prots);
        
        while(!proto_queue.empty()){
            uint32_t cur_prot = proto_queue.front();
            proto_queue.pop();
            
            if(cur_prot == 0){
                continue;
            }
            
            uint32_t prot_cnt;
            memcpy(&prot_cnt, buffer_const_sec+(cur_prot - sec_const_ptr->addr), sizeof(uint32_t));
            if(prot_cnt > 0){
                uint32_t* prot_list = new uint32_t[prot_cnt];
                if(prot_list == NULL){
                    return -1;
                }
                memcpy(prot_list, buffer_const_sec+(cur_prot - sec_const_ptr->addr)+sizeof(uint32_t), prot_cnt*sizeof(uint32_t));
                
                for(int idx = 0; idx < prot_cnt; ++idx){
                    if(prot_list[idx] >= sec_bare_data_ptr->addr && prot_list[idx] < (sec_bare_data_ptr->addr+sec_bare_data_ptr->size)){
                        prot_item prot_struct;
                        memcpy(&prot_struct, buffer_bare_data_ptr+(prot_list[idx]-sec_bare_data_ptr->addr), sizeof(prot_item));
                        
                        if(prot_struct.name_ptr >= sec_classname_ptr->addr && prot_struct.name_ptr < (sec_classname_ptr->addr+sec_classname_ptr->size)){
                            string prot_name((char*)(buffer_classname_sec+(prot_struct.name_ptr-sec_classname_ptr->addr)));
                            
                            map<string, set<string>>::iterator iter_prots = this->class_prots.find(cls_name);
                            if(iter_prots == this->class_prots.end()){
                                set<string> prots;
                                prots.insert(prot_name);
                                this->class_prots.insert(make_pair(cls_name, prots));
                            }else{
                                iter_prots->second.insert(prot_name);
                            }
                            
                            map<string, set<string>>::iterator iter_delegates = this->delegates_implementations.find(prot_name);
                            if(iter_delegates == this->delegates_implementations.end()){
                                set<string> implements;
                                implements.insert(cls_name);
                                this->delegates_implementations.insert(make_pair("<" + prot_name +">", implements));
                            }else{
                                iter_delegates->second.insert(cls_name);
                            }
                        }
                        
                        if(prot_struct.sub_prots > 0){
                            proto_queue.push(prot_struct.sub_prots);
                        }
                    }
                }
                delete [] prot_list;
            }
        }
        
        if(cls_data.instance != 0){
            uint32_t ivar_size_and_count[2];
            memcpy(ivar_size_and_count, buffer_const_sec + cls_data.instance - sec_const_ptr->addr, 2*sizeof(uint32_t));
            
            if(ivar_size_and_count[0] == sizeof(ivar_item) && ivar_size_and_count[1] > 0){
                ivar_item* ivar_items = new ivar_item[ivar_size_and_count[1]];
                if(ivar_items == NULL){
                    return -1;
                }
                
                memcpy(ivar_items, buffer_const_sec + cls_data.instance - sec_const_ptr->addr + 2*sizeof(uint32_t), ivar_size_and_count[1]*sizeof(ivar_item));
                
                for(int idx = 0; idx < ivar_size_and_count[1]; idx++){
                    /*
                     log ivar as AdMoGoInterstitial.configKey(@"NSString")
                     */
                    if(ivar_items[idx].ivar_name < sec_methname_ptr->addr || ivar_items[idx].ivar_type < sec_methtype_ptr->addr){
                        continue;
                    }
                    string ivar_full(cls_name);
                    ivar_full.append(".");
                    const char* sel_name_ptr = reinterpret_cast<const char*>(buffer_methname_sec + (ivar_items[idx].ivar_name-sec_methname_ptr->addr));
                    const char* file_boundary = reinterpret_cast<const char*>(this->file_buffer+this->file_len);
                    
                    if (sel_name_ptr >= file_boundary) {
                        continue;
                    }
                    
                    ivar_full.append(sel_name_ptr);
                    ivar_full.append("(");
                    ivar_full.append(reinterpret_cast<const char*>(buffer_methtype_sec + (ivar_items[idx].ivar_type-sec_methtype_ptr->addr)));
                    ivar_full.append(")");
                    this->references_map.insert(make_pair(ivar_items[idx].ivar_ref, pair<ref_type, string>(IVAR_FULL_REF, ivar_full)));
                }
                
                delete[] ivar_items;
            }
        }
        
        if(cls_item.meta_class < sec_data_ptr->addr || cls_item.meta_class > (sec_data_ptr->addr + sec_data_ptr->size)){
            continue;
        }
        
        class_item cls_meta_item;
        memcpy(&cls_meta_item, buffer_data_sec+(cls_item.meta_class-sec_data_ptr->addr), sizeof(class_item));
        if(cls_meta_item.class_data < sec_const_ptr->addr || cls_meta_item.class_data > (sec_const_ptr->addr + sec_const_ptr->size)){
            continue;
        }
        
        class_data cls_meta_data;
        memcpy(&cls_meta_data, buffer_const_sec+(cls_meta_item.class_data - sec_const_ptr->addr), sizeof(class_data));
        if(cls_meta_data.class_name < sec_classname_ptr->addr || cls_meta_data.class_name > (sec_classname_ptr->addr + sec_classname_ptr->size)){
            continue;
        }
        
        if(cls_meta_data.methods != 0){
            methods_in_class methods_meta_in_cls;
            memcpy(&methods_meta_in_cls, buffer_const_sec+(cls_meta_data.methods - sec_const_ptr->addr), sizeof(uint32_t)*2);
            
            if(methods_meta_in_cls.method_count > 0){
                methods_meta_in_cls.methods = new method_item[methods_meta_in_cls.method_count];
                if(methods_meta_in_cls.methods == NULL){
                    return -1;
                }
                
                memcpy(methods_meta_in_cls.methods, buffer_const_sec+(cls_meta_data.methods - sec_const_ptr->addr)+sizeof(uint32_t)*2, methods_meta_in_cls.method_count*sizeof(method_item));
                
                for(int idx = 0; idx < methods_meta_in_cls.method_count; idx++){
                    method_desc meth_desc;
                    meth_desc.class_name.append(cls_name);
                    meth_desc.method_addr = (methods_meta_in_cls.methods[idx].method_addr_plus_one/sizeof(uint32_t)*sizeof(uint32_t));
                    meth_desc.event = NON_EVENT;
                    meth_desc.upper_caller = "";
                    uint32_t meth_name_idx = methods_meta_in_cls.methods[idx].method_name - sec_methname_ptr->addr;
                    if(meth_name_idx > 0 && meth_name_idx < sec_methname_ptr->size){
                        meth_desc.method_name.append(reinterpret_cast<const char*>(buffer_methname_sec + meth_name_idx));
                        methods_addr2desc.insert(make_pair(meth_desc.method_addr, meth_desc));
                    }
                }
                delete [] methods_meta_in_cls.methods;
            }
        }
    }
    
    
    for(map<string, uint32_t>::iterator iter_class_super_addr = class_super_addr.begin(); iter_class_super_addr != class_super_addr.end(); ++iter_class_super_addr){
        map<uint32_t, string>::const_iterator iter_cls_data_addr2clsname = cls_data_addr2clsname.find(iter_class_super_addr->second);
        if(iter_cls_data_addr2clsname != cls_data_addr2clsname.end()){
            this->class_superclass.insert(make_pair(iter_class_super_addr->first, iter_cls_data_addr2clsname->second));
        }
    }
    
    /*
     begin extracting selector refs
     */
    uint32_t selref_base_addr = sec_selrefs_ptr->addr;
    for(int idx = 0; idx < selref_count; idx++){
        if(buffer_selrefs_ptr[idx] >= sec_methname_ptr->addr && buffer_selrefs_ptr[idx] < (sec_methname_ptr->addr+sec_methname_ptr->size)){
            this->references_map.insert(make_pair(selref_base_addr+idx*sizeof(uint32_t), pair<ref_type, string>(SEL_REF, string(reinterpret_cast<const char*>(buffer_methname_sec+buffer_selrefs_ptr[idx]-sec_methname_ptr->addr)))));
        }
    }
    
    /*
     begin extracting class refs
     */
    for(int idx = 0; idx < classref_count; idx++){
        if(buffer_classrefs_ptr[idx] >= sec_data_ptr->addr && buffer_classrefs_ptr[idx] < (sec_data_ptr->addr+sec_data_ptr->size)){
            /*class reference direct into __objc_data section*/
            map<uint32_t, string>::iterator iter = cls_data_addr2clsname.find(buffer_classrefs_ptr[idx]);
            if(iter != cls_data_addr2clsname.end()){
                this->references_map.insert(make_pair(sec_classrefs_ptr->addr+idx*sizeof(uint32_t), pair<ref_type, string>(CLASS_REF, iter->second)));
            }
        }
    }
    
    for (int idx = 0; idx < superref_count; idx++) {
        map<uint32_t, string>::iterator iter = cls_data_addr2clsname.find(buffer_superrefs_ptr[idx]);
        if(iter != cls_data_addr2clsname.end()){
            this->references_map.insert(make_pair(sec_superrefs_ptr->addr+idx*sizeof(uint32_t), pair<ref_type, string>(CLASS_REF, iter->second)));
        }
    }
    
    /*
     begin extracting cfstring
     */
    for(int idx = 0; idx < sec_cfstring_ptr->size/sizeof(cfstring_item); idx++){
        if(buffer_cfstring_ptr[idx].cstring_ref >= sec_cstring_ptr->addr && buffer_cfstring_ptr[idx].cstring_ref < (sec_cstring_ptr->addr+sec_cstring_ptr->size)){
            this->references_map.insert(make_pair(sec_cfstring_ptr->addr+idx*sizeof(cfstring_item), pair<ref_type, string>(CFSTRING_REF, string(reinterpret_cast<char*>(buffer_cstring_ptr+buffer_cfstring_ptr[idx].cstring_ref-sec_cstring_ptr->addr)))));
        }
    }
    
    /*
     begin extracting symbol stub
     */
    vector<string> symbols;
    struct symtab_command* symtab_ptr = reinterpret_cast<struct symtab_command*>(this->file_buffer+this->idx_symtab_cmd);
    struct nlist* buffer_symtab = reinterpret_cast<struct nlist*>(this->file_buffer+symtab_ptr->symoff);
    unsigned char* buffer_str = reinterpret_cast<unsigned char*>(this->file_buffer+symtab_ptr->stroff);
    uint32_t str_size = symtab_ptr->strsize;
    
    for(int idx = 0; idx < symtab_ptr->nsyms; idx++){
        uint32_t cur_size = buffer_symtab[idx].n_un.n_strx;
        if(cur_size > 0 && cur_size < str_size){
            string symbol_item(reinterpret_cast<const char*>(&(buffer_str[buffer_symtab[idx].n_un.n_strx])));
            string::size_type pos = symbol_item.find("_OBJC_CLASS_$_");
            if(pos != string::npos){
                symbol_item = symbol_item.substr(pos+strlen("_OBJC_CLASS_$_"));
            }else{
                pos = symbol_item.find("_OBJC_METACLASS_$_");
                if(pos != string::npos){
                    symbol_item = symbol_item.substr(pos+strlen("_OBJC_METACLASS_$_"));
                }
            }
            
            symbols.push_back(symbol_item);
        }
    }
    
    if((this->sections.count("__picsymbolstub4") <= 0) && (this->sections.count("__symbolstub1") <= 0 && (this->sections.count("__symbol_stub4")) <= 0)){
        cout << "section __picsymbolstub4/__symbolstub1 not found" << endl;
        return -1;
    }
    
    it = this->sections.find("__picsymbolstub4");
    if(it == this->sections.end()){
        it = this->sections.find("__symbolstub1");
    }
    if(it == this->sections.end()){
        it = this->sections.find("__symbol_stub4");
    }
    
    struct section* sec_stub_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    uint32_t addr_stub = sec_stub_ptr->addr;
    uint32_t sizeof_stub = (sec_stub_ptr->reserved2>0)?sec_stub_ptr->reserved2:16;
    uint32_t in_indref_off = (sec_stub_ptr->reserved1>0)?sec_stub_ptr->reserved1:0;

    if(this->idx_dysymtab_cmd > 0){
        struct dysymtab_command* dysymtab_ptr = reinterpret_cast<struct dysymtab_command*>(this->file_buffer+this->idx_dysymtab_cmd);
        uint32_t* buffer_dysymtab = reinterpret_cast<uint32_t*>(this->file_buffer+dysymtab_ptr->indirectsymoff);

        for(int idx = 0; idx < sec_stub_ptr->size/sizeof_stub; idx++){
            uint32_t addr_stub4_item = addr_stub + idx*sizeof_stub;
            uint32_t idx_in_indref = idx + in_indref_off;

            if(idx_in_indref < dysymtab_ptr->nindirectsyms){
                uint32_t idx_in_sym_tab = buffer_dysymtab[idx_in_indref];
                if(idx_in_sym_tab > 0 && idx_in_sym_tab < symbols.size()){
                    this->references_map.insert(make_pair(addr_stub4_item, pair<ref_type, string>(SYMBOL_STUB_REF, symbols[idx_in_sym_tab])));
                }
            }
        }

    /*
 *      begin extracting external relocation info
 *           */
        const struct relocation_info* const reloc_start = reinterpret_cast<struct relocation_info*>(this->file_buffer+dysymtab_ptr->extreloff);
        const struct relocation_info* const reloc_end = &reloc_start[dysymtab_ptr->nextrel];
        for(const struct relocation_info* reloc = reloc_start; reloc < reloc_end; reloc++){
            if((reloc->r_address & R_SCATTERED) == 0){
                if(reloc->r_symbolnum == R_ABS){
                    /*ignore absolute relocations*/
                }else if(reloc->r_length == RELOC_SIZE){
                    if(reloc->r_extern == 1 && reloc->r_type == GENERIC_RELOC_VANILLA){
                        if(reloc->r_symbolnum >= 0 && reloc->r_symbolnum < symbols.size()){
                            this->references_map.insert(make_pair(reloc->r_address, pair<ref_type, string>(RELOC_BIND_TYPE, symbols[reloc->r_symbolnum])));
                        }
                    }else{
                        cout << "relocation not GENERIC_RELOC_VANILLA type" << endl;
                    }
                }else{
                    cout << "bad relocation length" << endl;
                    break;
                }
            }else{
                cout << "encountered scattered relocation entry" << endl;
            }
        }
    }
    
    /*
     begin extracting binding info
     */
    
    if(this->idx_dyld_info_cmd < this->file_len && this->idx_dyld_info_cmd > 0){
        struct dyld_info_command* dyld_info_ptr = reinterpret_cast<struct dyld_info_command*>(this->file_buffer+this->idx_dyld_info_cmd);
        struct segment_command* seg_data_ptr = reinterpret_cast<struct segment_command*>(this->file_buffer+this->idx_data_seg);
        
        const uint8_t* const bind_start = this->file_buffer+dyld_info_ptr->bind_off;
        const uint8_t* const bind_end = bind_start+dyld_info_ptr->bind_size;
        const uint8_t* bind_p = bind_start;
        uint8_t type = 0;
        int segmentIndex = 0;
        intptr_t addend = 0;
        bool done = false;
        uint8_t symboFlags = 0;
        uintptr_t libraryOrdinal = 0;
        const char* symbolName = NULL;
        uintptr_t address = 0;
        uintptr_t segmentEndAddress = 0;
        uintptr_t count;
        uintptr_t skip;
        
        uint32_t classref_base = sec_classrefs_ptr->addr;
        uint32_t classref_end = classref_base+sec_classrefs_ptr->size;
        
        while(!done && bind_p < bind_end){
            uint8_t immediate = *bind_p & BIND_IMMEDIATE_MASK;
            uint8_t opcode = *bind_p & BIND_OPCODE_MASK;
            ++bind_p;
            
            switch(opcode){
                case BIND_OPCODE_DONE:
                    done = true;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                    libraryOrdinal = immediate;
                    break;
                case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                    libraryOrdinal = read_uleb128(bind_p, bind_end);
                    break;
                case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                    /* the special ordinals are negative numbers */
                    if ( immediate == 0 )
                        libraryOrdinal = 0;
                    else {
                        int8_t signExtended = BIND_OPCODE_MASK | immediate;
                        libraryOrdinal = signExtended;
                    }
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    symbolName = (char*)bind_p;
                    symboFlags = immediate;
                    while (*bind_p != '\0')
                        ++bind_p;
                    ++bind_p;
                    break;
                case BIND_OPCODE_SET_TYPE_IMM:
                    type = immediate;
                    break;
                case BIND_OPCODE_SET_ADDEND_SLEB:
                    addend = read_sleb128(bind_p, bind_end);
                    break;
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:{
                    segmentIndex = immediate;
                    const int IDX_DATA = 2;
                    /*only DATA segment is allowed here*/
                    if(segmentIndex == IDX_DATA){
                        address = seg_data_ptr->vmaddr + read_uleb128(bind_p, bind_end);
                        segmentEndAddress = seg_data_ptr->vmaddr+seg_data_ptr->vmsize;
                    }else{
                        done = true;
                    }
                }
                    break;
                case BIND_OPCODE_ADD_ADDR_ULEB:
                    address += read_uleb128(bind_p, bind_end);
                    break;
                case BIND_OPCODE_DO_BIND:
                    if ( address >= segmentEndAddress ){
                        done = true;
                    }
                    
                    if(address >= classref_base && address < classref_end){
                        string symbolStr(symbolName);
                        string::size_type pos = symbolStr.find("_OBJC_CLASS_$_");
                        if(pos != string::npos){
                            symbolStr = symbolStr.substr(pos+strlen("_OBJC_CLASS_$_"));
                        }
                        
                        this->references_map.insert(make_pair(address, pair<ref_type, string>(RELOC_BIND_TYPE, symbolStr)));
                        /*cout << "bind0: " << symbolStr << " addr:" << hex << address << endl;*/
                    }
                    
                    address += sizeof(uint32_t);
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                    if ( address >= segmentEndAddress ){
                        done = true;
                    }
                    if(address >= classref_base && address < classref_end){
                        string symbolStr(symbolName);
                        string::size_type pos = symbolStr.find("_OBJC_CLASS_$_");
                        if(pos != string::npos){
                            symbolStr = symbolStr.substr(pos+strlen("_OBJC_CLASS_$_"));
                        }
                        
                        this->references_map.insert(make_pair(address, pair<ref_type, string>(RELOC_BIND_TYPE, symbolStr)));
                        /*cout << "bind1: " << symbolStr << " addr:" << hex << address << endl;*/
                    }
                    
                    address += read_uleb128(bind_p, bind_end) + sizeof(uint32_t);
                    break;
                case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                    if ( address >= segmentEndAddress ){
                        done = true;
                    }
                    
                    if(address >= classref_base && address < classref_end){
                        string symbolStr(symbolName);
                        string::size_type pos = symbolStr.find("_OBJC_CLASS_$_");
                        if(pos != string::npos){
                            symbolStr = symbolStr.substr(pos+strlen("_OBJC_CLASS_$_"));
                        }
                        
                        this->references_map.insert(make_pair(address, pair<ref_type, string>(RELOC_BIND_TYPE, symbolStr)));
                        /*cout << "bind2: " << symbolStr << " addr:" << hex << address << endl;*/
                    }
                    
                    address += immediate*sizeof(uint32_t) + sizeof(uint32_t);
                    break;
                case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    if(address >= classref_base && address < classref_end){
                        string symbolStr(symbolName);
                        string::size_type pos = symbolStr.find("_OBJC_CLASS_$_");
                        if(pos != string::npos){
                            symbolStr = symbolStr.substr(pos+strlen("_OBJC_CLASS_$_"));
                        }
                        
                        this->references_map.insert(make_pair(address, pair<ref_type, string>(RELOC_BIND_TYPE, symbolStr)));
                        /*cout << "bind3: " << symbolStr << " addr:" << hex << address << endl;*/
                    }
                    
                    count = read_uleb128(bind_p, bind_end);
                    skip = read_uleb128(bind_p, bind_end);
                    for (uint32_t i=0; i < count; ++i) {
                        if ( address >= segmentEndAddress ){
                            done = true;
                        }
                        address += skip + sizeof(uint32_t);
                    }
                    break;
                default:
                    cout << "bad bind opcode " << *bind_p << " in bind info" << endl;
            }
        }
    }else{
        cout << "LC_DYLD_INFO_ONLY segment not found" << endl;
    }
    return 0;
}

/*
 disassemble all defined methods and extract detailed references.
 */
int mach_desc::get_reference_details(){
    map<string, size_t>::const_iterator iter_section = this->sections.find("__text");
    if(iter_section == this->sections.end()){
        cout << "error __text section not found!" << endl;
        return -1;
    }
    
    /*most functions starts with instructions in test_instr_arr*/
    set<string> test_instr_set = {"push", "mov", "ldr", "cmp", "add"};
    
    struct section* text_section = reinterpret_cast<struct section*>(this->file_buffer+iter_section->second);
    
    iter_section = this->sections.find("__cstring");
    if(iter_section == this->sections.end()){
        cout << "__cstring not found" << endl;
        return -1;
    }
    struct section* sec_cstring_ptr = reinterpret_cast<struct section*>(this->file_buffer+iter_section->second);
    unsigned char* buffer_cstring_ptr = this->file_buffer+sec_cstring_ptr->offset;
    
    uint32_t cstring_addr_start = sec_cstring_ptr->addr;
    uint32_t cstring_addr_end = sec_cstring_ptr->addr+sec_cstring_ptr->size;
    
    for (map<uint32_t, method_desc>::iterator iter_meth = this->methods_addr2desc.begin(); iter_meth != this->methods_addr2desc.end(); ++iter_meth) {
        uint32_t method_vm_addr = iter_meth->first;
        if(++iter_meth == this->methods_addr2desc.end()){
            break;
        }
        uint32_t next_method_addr = iter_meth->first;
        --iter_meth;
        if(next_method_addr<=method_vm_addr){
            cout << "failed to detect method termination on __" << iter_meth->second.class_name << "_" << iter_meth->second.method_name << "_" << endl;
            continue;
        }
        
        string meth_name = iter_meth->second.class_name+":"+iter_meth->second.method_name;
        
        /*
         add extra class reference
         */
        if(iter_meth->second.class_name.length() > 0){
            iter_meth->second.meth_all_refs.push_back(make_pair(CLASS_REF, iter_meth->second.class_name));
        }
        
        /*Dissable function at method_code*/
        unsigned char* method_code = this->file_buffer + text_section->offset + method_vm_addr - text_section->addr;
        /*
         test whether ARM or Thumb
         */
        bool is_ARM = false;
        csh handle;
        cs_insn* insn;
        cs_err err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
        if (err) {
            cout << "Failed on cs_open() with error:" << err << endl;
            break;
        }
        cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
        
        size_t count = cs_disasm(handle, method_code, 4, method_vm_addr, 0, &insn);
        if(count > 0){
            if(test_instr_set.count(insn[0].mnemonic) > 0){
                cs_free(insn, count);
                cs_close(&handle);
                is_ARM = true;
            }else{
                cs_free(insn, count);
                cs_close(&handle);
            }
        }else{
            cs_close(&handle);
        }
        
        err = cs_open(CS_ARCH_ARM, is_ARM?CS_MODE_ARM:CS_MODE_THUMB, &handle);
        if (err) {
            cout << "Failed on cs_open() with error:" << err << endl;
            break;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        
        count = cs_disasm(handle, method_code, next_method_addr-method_vm_addr, method_vm_addr, 0, &insn);
        /*
         Mainly detect following schme
         Thumb Mode
         0x952c4:	movw	r0, #0x837c
         0x952c8:	movt	r0, #0xa4
         0x952d4:	add	r0, pc
         
         0x6d46:	ldr	r0, [pc, #0x1c]
         0x6d48:	add	r0, pc
         0x6d4a:	ldr	r1, [r0]
         
         ARM Mode
         0x29a84:	ldr	ip, [pc, #8]
         0x29a88:	add	ip, pc, ip
         0x29a8c:	ldr	pc, [ip]
         */
        
        /*
         immediate values may refer to class/selector/string/other symbols
         */
        map<string, uint32_t> unresolved_imm;
        map<string, uint32_t>::iterator iter;
        set<string> mov_instr = {"mov", "movw", "movt", "ldr"};
        set<string> goto_instr = {"b", "bl", "bx", "b.w", "blx"};
        set<string> jmp_out_instr = {"b", "bx", "b.w"};
        set<string> add_instr = {"adc", "add"};
        
        if (count){
            for(int idx = 0; (idx < count) && (insn[idx].detail != NULL); idx++){
                cs_arm* arm = &(insn[idx].detail->arm);
                if(mov_instr.count(insn[idx].mnemonic) > 0){
                    /*log move immediate value to register*/
                    if(arm->op_count >= 2 && arm->operands[0].type == ARM_OP_REG){
                        const char* reg_name = cs_reg_name(handle, arm->operands[0].reg);
                        uint32_t imm_val = 0;
                        
                        if(arm->operands[1].type == ARM_OP_IMM){
                            imm_val = arm->operands[1].imm;
                            if(!strcmp("movt", insn[idx].mnemonic)){
                                imm_val = imm_val << 16;
                            }
                        }else if(arm->operands[1].type == ARM_OP_MEM){
                            const char* base_reg = cs_reg_name(handle, arm->operands[1].mem.base);
                            int disp = arm->operands[1].mem.disp;
                            if(!strcmp("ldr", insn[idx].mnemonic) && !strcmp("pc", base_reg) && disp > 0){
                                uint32_t mem_addr = (disp + (uint32_t)insn[idx].address + 2*(is_ARM?4:2))&0xfffffffc;
                                if(mem_addr >= text_section->addr && mem_addr < (text_section->addr + text_section->size)){
                                    imm_val = *(uint32_t*)(this->file_buffer+text_section->offset+mem_addr-text_section->addr);
                                }
                            }
                        }
                        
                        if(imm_val > 0){
                            iter = unresolved_imm.find(reg_name);
                            if(iter != unresolved_imm.end()){
                                imm_val += iter->second;
                                unresolved_imm.erase(iter);
                                unresolved_imm.insert(make_pair(reg_name, imm_val));
                            }else{
                                unresolved_imm.insert(make_pair(reg_name, imm_val));
                            }
                        }else{
                            unresolved_imm.erase(reg_name);
                        }
                    }
                }else if(add_instr.count(insn[idx].mnemonic) > 0){
                    /*if "add register, pc" happens*/
                    if(arm->op_count >= 2 && arm->operands[0].type == ARM_OP_REG){
                        const char* reg_name = cs_reg_name(handle, arm->operands[0].reg);
                        if(arm->operands[1].type == ARM_OP_REG && !strcmp("pc", cs_reg_name(handle, arm->operands[1].reg))){
                            iter = unresolved_imm.find(reg_name);
                            if(iter != unresolved_imm.end()){
                                uint32_t reg_contains_imm = iter->second + (uint32_t)insn[idx].address + 2*(is_ARM?4:2);
                                map< uint32_t, pair<ref_type, string> >::iterator iterator = this->references_map.find(reg_contains_imm);
                                if(iterator != this->references_map.end()){
                                    if(find(iter_meth->second.meth_all_refs.begin(), iter_meth->second.meth_all_refs.end(), iterator->second) == iter_meth->second.meth_all_refs.end() && iterator->second.second.length() > 0){
                                        
                                        iter_meth->second.meth_all_refs.push_back(iterator->second);
                                        
                                        if(iterator->second.first == IVAR_FULL_REF){
                                            string ivar_full(iterator->second.second);
                                            string::size_type pos = ivar_full.find("@\"");
                                            string::size_type pos_end = ivar_full.rfind("\"");
                                            if(pos != string::npos && pos_end != string::npos && pos_end > (pos+2)){
                                                ivar_full = ivar_full.substr(pos+2, pos_end-(pos+2));
                                                iter_meth->second.meth_all_refs.push_back(make_pair(IVAR_TYPE_REF, ivar_full));
                                            }
                                            
                                            /*add ivar usage map*/
                                            map<string, set<string>>::iterator ivar_usage_iter = this->ivar_usage_map.find(iterator->second.second);
                                            if(ivar_usage_iter != this->ivar_usage_map.end()){
                                                ivar_usage_iter->second.insert(meth_name);
                                            }else{
                                                set<string> ivar_usage_set;
                                                ivar_usage_set.insert(meth_name);
                                                this->ivar_usage_map.insert(make_pair(iterator->second.second, ivar_usage_set));
                                            }
                                        }
                                    }
                                }else if(reg_contains_imm >= cstring_addr_start && reg_contains_imm < cstring_addr_end){
                                    char* item = (char*)buffer_cstring_ptr+(reg_contains_imm-cstring_addr_start);
                                    iter_meth->second.meth_all_refs.push_back(make_pair(CFSTRING_REF, string(item)));
                                }
                                unresolved_imm.erase(reg_name);
                            }
                        }else{
                            unresolved_imm.erase(reg_name);
                        }
                    }
                }else if(goto_instr.count(insn[idx].mnemonic) > 0){
                    for(int j = 0; j < arm->op_count; j++){
                        cs_arm_op *op = &(arm->operands[j]);
                        if((int)op->type == ARM_OP_IMM){
                            map< uint32_t, pair<ref_type, string> >::const_iterator iterator = this->references_map.find(op->imm);
                            if(iterator != this->references_map.end()){
                                if(find(iter_meth->second.meth_all_refs.begin(), iter_meth->second.meth_all_refs.end(), iterator->second) == iter_meth->second.meth_all_refs.end() && iterator->second.second.length() > 0){
                                    iter_meth->second.meth_all_refs.push_back(iterator->second);
                                    
                                    if(iterator->second.first == IVAR_FULL_REF){
                                        string ivar_full(iterator->second.second);
                                        string::size_type pos = ivar_full.find("@\"");
                                        string::size_type pos_end = ivar_full.rfind("\"");
                                        if(pos != string::npos && pos_end != string::npos && pos_end > (pos+2)){
                                            ivar_full = ivar_full.substr(pos+2, pos_end-(pos+2));
                                            iter_meth->second.meth_all_refs.push_back(make_pair(IVAR_TYPE_REF, ivar_full));
                                        }
                                        
                                        /*add ivar usage map*/
                                        map<string, set<string>>::iterator ivar_usage_iter = this->ivar_usage_map.find(iterator->second.second);
                                        if(ivar_usage_iter != this->ivar_usage_map.end()){
                                            ivar_usage_iter->second.insert(meth_name);
                                        }else{
                                            set<string> ivar_usage_set;
                                            ivar_usage_set.insert(meth_name);
                                            this->ivar_usage_map.insert(make_pair(iterator->second.second, ivar_usage_set));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    /*if(jmp_out_instr.count(insn[idx].mnemonic) > 0){
                        b, bx, b.w jump without link, indicates boundary of this function
                        break;
                    }*/
                } else {
                    /*register may be used in other instructions, remove it in unresolved_imm*/
                    for(int m = 0; m < arm->op_count; m++){
                        if(arm->operands[m].type == ARM_OP_REG){
                            unresolved_imm.erase(cs_reg_name(handle, arm->operands[m].reg));
                        }
                    }
                }
            }
            cs_free(insn, count);
        }
        cs_close(&handle);
    }
    
    for (map<uint32_t, method_desc>::iterator iter_meth = this->methods_addr2desc.begin(); iter_meth != this->methods_addr2desc.end(); ++iter_meth){
        string method_name(iter_meth->second.class_name);
        method_name.append(":").append(iter_meth->second.method_name);
        for(vector<pair<ref_type, string>>::iterator iter_const = iter_meth->second.meth_all_refs.begin(); iter_const != iter_meth->second.meth_all_refs.end(); iter_const++){
            /*
             convert delegates to implementation class, remain only one implementation
             */
            map<string, set<string>>::iterator iter_delegates = this->delegates_implementations.find(iter_const->second);
            /*
             iter_delegates->second.size() == 1 filters out most developer defined delegates
             */
            if(iter_delegates != this->delegates_implementations.end() && iter_delegates->second.size() == 1){
                iter_const->first = DELEGATE_REF;
                iter_const->second = *(iter_delegates->second.begin());
            }
            /*
             initialize const_in_methods
             */
            map_str_2_vec_pair_iter iter_str = this->const_in_methods.find(iter_const->second);
            if(iter_str == this->const_in_methods.end()){
                vector<pair<ref_type, string>> vec;
                vec.push_back(make_pair(iter_const->first, method_name));
                this->const_in_methods.insert(make_pair(iter_const->second, vec));
            }else{
                iter_str->second.push_back(make_pair(iter_const->first, method_name));
            }
        }
        
        this->methods_name2desc.insert(make_pair(method_name, iter_meth->second));
    }
    return 0;
}

map<string, set<string>> mach_desc::get_class_2_strings(bool only_cfstring, size_t min_len) const{
    map<string, set<string>> class_2_strings;
    if(this->methods_name2desc.size() <= 0){
        return class_2_strings;
    }
    
    for(map<string, method_desc>::const_iterator iter_methods = this->methods_name2desc.begin(); iter_methods != this->methods_name2desc.end(); ++iter_methods){
        for(vector<pair<ref_type, string>>::const_iterator iter_refs = iter_methods->second.meth_all_refs.begin(); iter_refs != iter_methods->second.meth_all_refs.end(); ++iter_refs){
            
            if(!only_cfstring || (only_cfstring && iter_refs->first == CFSTRING_REF)){
                if(iter_methods->second.class_name.length() > 0 && iter_refs->second.length() > min_len){
                    map<string, set<string>>::iterator iter_class_2_strings = class_2_strings.find(iter_methods->second.class_name);
                    if(iter_class_2_strings != class_2_strings.end()){
                        iter_class_2_strings->second.insert(iter_refs->second);
                    }else{
                        set<string> strs;
                        strs.insert(iter_refs->second);
                        class_2_strings.insert(make_pair(iter_methods->second.class_name, strs));
                    }
                }
            }
            
        }
    }
    return class_2_strings;
}

/*
 write method_use_strings into ref_file_path
 */
void mach_desc::export_references(){
    //put_methods_in_db(this->methods_name2desc, this->file_sha256.c_str());
    
    bool only_export = false;
    /*
     find classes that directly or indirectly related with JSExport
     */
    set<string> exported_classes;
    for(map<string, set<string>>::const_iterator iter_class_prots = this->class_prots.begin(); iter_class_prots != this->class_prots.end(); ++ iter_class_prots){
        bool is_export = false;
        
        for(set<string>::const_iterator iter_prots = iter_class_prots->second.begin(); iter_prots != iter_class_prots->second.end(); ++iter_prots){
            if((*iter_prots).find("JSExport") != std::string::npos){
                is_export = true;
                break;
            }
        }
        
        if(is_export){
            exported_classes.insert(iter_class_prots->first);
        }
    }
    
    /*
     Inheriting interface from parent class
     */
    for(map<string, string>::const_iterator iter_class_superclass = this->class_superclass.begin(); iter_class_superclass != this->class_superclass.end(); ++iter_class_superclass){
        if(exported_classes.find(iter_class_superclass->second) != exported_classes.end()){
            exported_classes.insert(iter_class_superclass->first);
        }
    }

    dump_to_json(only_export, exported_classes, this->methods_name2desc, this->file_sha256.c_str());
}

set<string> mach_desc::extend_class_set_by_const(const set<string>& anchor_class_set, const vector<pair<string, set<string>>>& android_cls_2_strings) const{
    map<string, set<string>> ios_cls_2_strings = this->get_class_2_strings();
    /*classes that do not share enough string with Android*/
    set<string> upper_candidate_classes;
    set<string> defined_classes;
    
    cout << endl << "candidata classes:[";
    for(map<string, set<string>>::const_iterator iter_cls_2_strings = ios_cls_2_strings.begin(); iter_cls_2_strings != ios_cls_2_strings.end(); ++iter_cls_2_strings){
        defined_classes.insert(iter_cls_2_strings->first);
        
        /*restrict string size of ios class*/
        if(iter_cls_2_strings->second.size() < 8){
            continue;
        }
        
        pair<string, int> chosen_android_cls = make_pair("", 0);
        for(vector<pair<string, set<string>>>::const_iterator iter_android_cls_2_strings = android_cls_2_strings.begin(); iter_android_cls_2_strings != android_cls_2_strings.end(); ++iter_android_cls_2_strings){
            /*restrict string size of android class*/
            if(iter_android_cls_2_strings->second.size() < 8){
                continue;
            }
            
            set<string> comm_set = measure_set_similarity(iter_cls_2_strings->second, iter_android_cls_2_strings->second);
            
            if(comm_set.size() > chosen_android_cls.second){
                chosen_android_cls = make_pair(iter_android_cls_2_strings->first, comm_set.size());
                if(chosen_android_cls.second >= 3){
                    upper_candidate_classes.insert(iter_cls_2_strings->first);
                    break;
                }
            }
        }
        
        cout << iter_cls_2_strings->first << "(" << chosen_android_cls.first << "/" << chosen_android_cls.second << "/" << iter_cls_2_strings->second.size() << "),";
    }
    cout << "]" << endl;
    
    set<string> classes_set;
    classes_set.insert(anchor_class_set.begin(), anchor_class_set.end());
    
    int round_gain;
    do{
        round_gain = 0;
        
        /*
         search upwards for more classes
         */
        size_t class_gain = 0;
        do{
            class_gain = 0;
            
            for(map<string, method_desc>::const_iterator iter = this->methods_name2desc.begin(); iter != this->methods_name2desc.end(); ++iter){
                if(classes_set.find(iter->second.class_name) != classes_set.end() || upper_candidate_classes.find(iter->second.class_name) == upper_candidate_classes.end()){
                    continue;
                }
                
                vector<pair<ref_type, string>> vec_strs = iter->second.meth_all_refs;
                for(vector<pair<ref_type, string> >::iterator iter_vec = vec_strs.begin(); iter_vec != vec_strs.end(); iter_vec++){
                    if((iter_vec->first == CLASS_REF || iter_vec->first == SUPER_CLASS_REF) && classes_set.count(iter_vec->second)>0){
                        classes_set.insert(iter->second.class_name);
                        ++class_gain;
                        
                        ++round_gain;
                        break;
                    }
                }
            }
        }while(class_gain > 0);
        
        /*
         search downwards for more classes
         */
        do{
            class_gain = 0;
            
            for(map<string, method_desc>::const_iterator iter = this->methods_name2desc.begin(); iter != this->methods_name2desc.end(); ++iter){
                if(classes_set.find(iter->second.class_name) == classes_set.end()){
                    continue;
                }
                vector<pair<ref_type, string> > vec_strs = iter->second.meth_all_refs;
                for(vector<pair<ref_type, string> >::iterator iter_vec = vec_strs.begin(); iter_vec != vec_strs.end(); iter_vec++){
                    if((iter_vec->first == CLASS_REF || iter_vec->first == SUPER_CLASS_REF) && defined_classes.count(iter_vec->second) > 0 && classes_set.count(iter_vec->second) <= 0){
                        classes_set.insert(iter_vec->second);
                        ++class_gain;
                        
                        ++round_gain;
                    }
                }
            }
        }while(class_gain > 0);
    }while(round_gain > 0);
    
    
     cout << "extend class in " << this->file_path << endl;
     cout << "from[";
     for(set<string>::const_iterator debug_iter = anchor_class_set.begin(); debug_iter != anchor_class_set.end(); ++debug_iter){
     cout << *debug_iter << ",";
     }
     cout << "]" << endl;
     
     cout << "to[";
     for(set<string>::const_iterator debug_iter = classes_set.begin(); debug_iter != classes_set.end(); ++debug_iter){
     cout << *debug_iter << ",";
     }
     cout << "]" << endl;
     
    return classes_set;
}

/*
 UI events
 addTarget:action:forControlEvents:
 
 //tuple<event_loc, event_type, keys>
 vector<tuple<string, event_type, string>> events;
 */
void mach_desc::get_ui_events(){
    set<string> view_lifecycle_event_set = {"viewDidLoad", "viewWillAppear:", "viewWillDisappear:", "viewDidUnload", "init", "dealloc"};
    
    map<string, vector<pair<ref_type, string>>> ui_selector_and_classes;
    
    for(map<string, method_desc>::iterator iter_method = this->methods_name2desc.begin(); iter_method != this->methods_name2desc.end(); iter_method++){
        vec_pair_type_string_iter_const iter_action = find(iter_method->second.meth_all_refs.begin(), iter_method->second.meth_all_refs.end(), pair<ref_type, string>(SEL_REF, "addTarget:action:forControlEvents:"));
        if(iter_action != iter_method->second.meth_all_refs.end()){
            if(++iter_action != iter_method->second.meth_all_refs.end()){
                ui_selector_and_classes.insert(make_pair(iter_action->second, iter_method->second.meth_all_refs));
            }
        }
        
        vec_pair_type_string_iter_const iter_network_cls = find(iter_method->second.meth_all_refs.begin(), iter_method->second.meth_all_refs.end(), pair<ref_type, string>(CLASS_REF, "NSURLConnection"));
        vec_pair_type_string_iter_const iter_network_ivar = find(iter_method->second.meth_all_refs.begin(), iter_method->second.meth_all_refs.end(), pair<ref_type, string>(IVAR_TYPE_REF, "NSURLConnection"));
        if(iter_network_cls != iter_method->second.meth_all_refs.end() || iter_network_ivar != iter_method->second.meth_all_refs.end()){
            iter_method->second.event |= NETWORK_EVENT;
            iter_method->second.event_property.append("NetworkEvent#");
        }
        
        if(view_lifecycle_event_set.count(iter_method->second.method_name) > 0){
            iter_method->second.event |= VIEW_LIFECYCLE_EVENT;
        }
    }
    
    //choose methods that constains selectors
    for(map<string, method_desc>::iterator iter_method = this->methods_name2desc.begin(); iter_method != this->methods_name2desc.end(); iter_method++){
        string cur_class = iter_method->second.class_name;
        string cur_selector = iter_method->second.method_name;
        
        map<string, vector<pair<ref_type, string>>>::iterator iter_ui = ui_selector_and_classes.find(cur_selector);
        if(iter_ui != ui_selector_and_classes.end()){
            if(find(iter_ui->second.begin(), iter_ui->second.end(), make_pair(CLASS_REF, cur_class))!= iter_ui->second.end()){
                iter_method->second.event |= VIEW_ACTION_EVENT;
                iter_method->second.event_property.append("UIEvent#");
            }
        }
    }
}

/*
 interprete extracted references to method invocations.
 */
void mach_desc::post_process_invocations(){
    for(map<string, method_desc>::iterator iter_method = this->methods_name2desc.begin(); iter_method != this->methods_name2desc.end(); iter_method++){
        vector<string> except_selector_set;
        vector<string> selector_set;
        
        for(vec_pair_type_string_iter iter_strings = iter_method->second.meth_all_refs.begin(); iter_strings != iter_method->second.meth_all_refs.end(); iter_strings++){
            if(iter_strings->first == SEL_REF){
                selector_set.push_back(iter_strings->second);
            }else{
                except_selector_set.push_back(iter_strings->second);
            }
        }
        
        /*
         Class reference incomplete, since we did not
         */
        
        /*
         add super class of class_set into used_string, A->B, but B accept argument of uncertain type, so some selector in B may be incomplete. Then we try to find paired class in A
         */
        vector<string> class_set;
        class_set.insert(class_set.begin(), except_selector_set.begin(), except_selector_set.end());
        
        for(vector<string>::iterator iter_except_selector = except_selector_set.begin(); iter_except_selector != except_selector_set.end(); ++iter_except_selector){
            string cur_class = *iter_except_selector;
            map<string, string>::iterator iter_class_superclass = this->class_superclass.find(cur_class);
            if(iter_class_superclass != this->class_superclass.end()){
                cur_class = iter_class_superclass->second;
                iter_method->second.meth_all_refs.push_back(make_pair(SUPER_CLASS_REF, cur_class));
                class_set.push_back(cur_class);
            }
        }
        
        for(vector<string>::iterator iter_selector_vec = selector_set.begin(); iter_selector_vec != selector_set.end(); iter_selector_vec++){
            bool selector_completed = false;
            
            for(vector<string>::iterator iter_class_vec = class_set.begin(); iter_class_vec != class_set.end(); iter_class_vec++){
                string cur_invoke("");
                cur_invoke.append(*iter_class_vec).append(":").append(*iter_selector_vec);
                if(cur_invoke.length() <= 0){
                    continue;
                }
                
                if(this->methods_name2desc.find(cur_invoke) != this->methods_name2desc.end() || ALL_APIs.count(cur_invoke) > 0){
                    if(cur_invoke.compare(iter_method->first)){
                        iter_method->second.meth_all_refs.push_back(make_pair(METH_INVOKE, cur_invoke));
                        
                        map<string, method_desc>::iterator iter_calle = this->methods_name2desc.find(cur_invoke);
                        if(iter_calle != this->methods_name2desc.end()){
                            iter_calle->second.meth_all_refs.push_back(make_pair(REVERSE_METH_INVOKE, iter_method->first));
                        }
                    }
                    selector_completed = true;
                    break;
                }
            }
            
            if(!selector_completed){
                iter_method->second.meth_all_refs.push_back(make_pair(INCOMPLETE_METH_INVOKE, *iter_selector_vec));
                //cout << "incomplete selector " << *iter_selector_vec << " in " << iter_method->first << endl;
            }
        }
    }
}

/*
 Two steps:
 1) from known sensitve methods (methods with events, methods that used sensitive system APIs), search upwards for points;
 2) Use points retrieved from 1), look downwards for chains
 */
set<pair<uint32_t, vector<string>>> mach_desc::get_all_call_chains(set<string> classes_set, set<string> ios_strings){
    /*
     Find all sensitive methods
     */
    set<string> sensitive_methods;
    for(map<string, method_desc>::const_iterator iter_methods = this->methods_name2desc.begin(); iter_methods != this->methods_name2desc.end(); ++iter_methods){
        for(vector<pair<ref_type, string>>::const_iterator iter_meth_all_refs = iter_methods->second.meth_all_refs.begin(); iter_meth_all_refs != iter_methods->second.meth_all_refs.end(); ++iter_meth_all_refs){
            if(iter_meth_all_refs->first == CFSTRING_REF){
                string::size_type pos = iter_meth_all_refs->second.find(":");
                if(pos != string::npos){
                    string sub_ref = iter_meth_all_refs->second.substr(0, pos);
                    if(sub_ref.length() > 0 && URL_SCHEMAs.count(sub_ref) > 0){
                        sensitive_methods.insert(iter_methods->first);
                        break;
                    }
                }
            }else if(iter_meth_all_refs->first == METH_INVOKE && IOS_APIs.count(iter_meth_all_refs->second) > 0){
                sensitive_methods.insert(iter_methods->first);
                break;
            }
        }
    }
    
    /*
     From sensitive methods, search upwards for Points
     */
    set<string> collected_method_points;
    set<string> covered_methods_by_points;
    for(set<string>::const_iterator iter_sensitive_methods = sensitive_methods.begin(); iter_sensitive_methods != sensitive_methods.end(); ++iter_sensitive_methods){
        map<string, method_desc>::const_iterator iter_methods = this->methods_name2desc.find(*iter_sensitive_methods);
        if(iter_methods == this->methods_name2desc.end()){
            continue;
        }
        
        stack<method_desc> cur_point_stack;
        cur_point_stack.push(iter_methods->second);
        while(!cur_point_stack.empty()){
            method_desc meth = cur_point_stack.top();
            cur_point_stack.pop();
            
            string cur_meth("");
            cur_meth.append(meth.class_name).append(":").append(meth.method_name);
            
            if(covered_methods_by_points.count(cur_meth) > 0){
                continue;
            }
            covered_methods_by_points.insert(cur_meth);
            
            bool ended_at_this_point = true;
            for(vector<pair<ref_type, string>>::const_iterator iter_refs = meth.meth_all_refs.begin(); iter_refs != meth.meth_all_refs.end(); ++iter_refs){
                if(iter_refs->first == REVERSE_METH_INVOKE){
                    ended_at_this_point = false;
                    map<string, method_desc>::const_iterator iter_reverse_meth_invoke = this->methods_name2desc.find(iter_refs->second);
                    if(iter_reverse_meth_invoke != this->methods_name2desc.end()){
                        cur_point_stack.push(iter_reverse_meth_invoke->second);
                    }
                }
            }
            
            if(ended_at_this_point){
                collected_method_points.insert(cur_meth);
            }
        }
    }
    
    /*
     Use points, look downwards for chains
     Format: chain stored in vector<string>, also related string
     */
    set<pair<uint32_t, vector<string>>> call_chains;
    
    for(map<string, method_desc>::const_iterator iter_methods = this->methods_name2desc.begin(); iter_methods != this->methods_name2desc.end(); ++iter_methods){
        if(collected_method_points.count(iter_methods->first) <= 0){
            continue;
        }
        
        vector<string> cur_chain;
        uint32_t cur_event = 0;
        
        bool belong_to_lib = false;
        stack<method_desc> cur_chain_stk;
        cur_chain_stk.push(iter_methods->second);
        
        while(!cur_chain_stk.empty()){
            method_desc meth = cur_chain_stk.top();
            cur_chain_stk.pop();
            
            string cur_name("");
            if(meth.method_addr > 0){
                cur_name.append(meth.class_name).append(":").append(meth.method_name);
                if(classes_set.find(meth.class_name) != classes_set.end()){
                    belong_to_lib = true;
                }
            }else{
                cur_name.append(meth.method_name);
            }
            
            if(find(cur_chain.begin(), cur_chain.end(), cur_name) == cur_chain.end() || meth.method_addr <= 0){
                cur_chain.push_back(cur_name);
                cur_event = cur_event|meth.event;
                collected_method_points.erase(cur_name);
            }
            
            if(cur_chain.size() > MAX_CALL_CHAIN_LEN){
                break;
            }
            
            for(vector<pair<ref_type, string>>::reverse_iterator iter_const = meth.meth_all_refs.rbegin(); iter_const != meth.meth_all_refs.rend(); ++iter_const){
                if(iter_const->first == METH_INVOKE){
                    if(find(cur_chain.begin(), cur_chain.end(), iter_const->second) == cur_chain.end()){
                        map<string, method_desc>::iterator iter_method = this->methods_name2desc.find(iter_const->second);
                        if(iter_method != this->methods_name2desc.end()){
                            iter_method->second.upper_caller = iter_methods->first;
                            cur_chain_stk.push(iter_method->second);
                        }else if(IOS_APIs.count(iter_const->second) > 0){
                            method_desc meth_desc;
                            meth_desc.method_name = iter_const->second;
                            meth_desc.method_addr = 0;
                            meth_desc.event = NON_EVENT;
                            meth_desc.upper_caller = "";
                            vector<pair<ref_type, string>> null_vec;
                            meth_desc.meth_all_refs = null_vec;
                            cur_chain_stk.push(meth_desc);
                        }
                    }
                } /*else if(iter_const->first == IVAR_FULL_REF){
                    map<string, set<string>>::const_iterator iter_ivar = this->ivar_usage_map.find(iter_const->second);
                    if(iter_ivar != this->ivar_usage_map.end() && iter_ivar->second.size() > 0){
                        for(set<string>::iterator iter_ivar_usage = iter_ivar->second.begin(); iter_ivar_usage != iter_ivar->second.end(); iter_ivar_usage++){
                            if(cur_name.compare(*iter_ivar_usage) && find(cur_chain.begin(), cur_chain.end(), *iter_ivar_usage) == cur_chain.end()){
                                map<string, method_desc>::const_iterator iter_method = this->methods_name2desc.find(*iter_ivar_usage);
                                if(iter_method != this->methods_name2desc.end()){
                                    cur_chain_stk.push(iter_method->second);
                                }
                            }
                        }
                    }
                   }*/
                else if(iter_const->first == INCOMPLETE_METH_INVOKE){
                    if(iter_methods->second.upper_caller.length() > 0){
                        map<string, method_desc>::iterator iter_upper_caller = this->methods_name2desc.find(iter_methods->second.upper_caller);
                        if(iter_upper_caller != this->methods_name2desc.end()){
                            for(vector<pair<ref_type, string>>::const_iterator iter_meth_all_refs = iter_upper_caller->second.meth_all_refs.begin(); iter_meth_all_refs != iter_upper_caller->second.meth_all_refs.end(); ++iter_meth_all_refs){
                                if(iter_meth_all_refs->first == CLASS_REF || iter_meth_all_refs->first == SUPER_CLASS_REF){
                                    string filled_meth = string("").append(iter_meth_all_refs->second).append(":").append(iter_const->second);
                                    map<string, method_desc>::iterator iter_filled_meth = this->methods_name2desc.find(filled_meth);
                                    
                                    if(iter_filled_meth != this->methods_name2desc.end() && find(cur_chain.begin(), cur_chain.end(), iter_filled_meth->first) == cur_chain.end()){
                                        iter_filled_meth->second.upper_caller = iter_methods->first;
                                        cur_chain_stk.push(iter_filled_meth->second);
                                    }
                                }
                            }
                        }
                    }
                }else if(ios_strings.count(iter_const->second) > 0){
                    method_desc meth_desc;
                    meth_desc.method_name = string("\"").append(iter_const->second).append("\"");
                    meth_desc.method_addr = 0;
                    meth_desc.event = NON_EVENT;
                    vector<pair<ref_type, string>> null_vec;
                    meth_desc.meth_all_refs = null_vec;
                    meth_desc.upper_caller = "";
                    cur_chain_stk.push(meth_desc);
                }
            }
        }
        
        if(belong_to_lib && cur_chain.size() > 2){
            call_chains.insert(make_pair(cur_event, cur_chain));
        }
    }
    return call_chains;
}

set<string> mach_desc::get_string_related_with_classes(const set<string>& classes, bool only_cfstring, size_t min_len){
    set<string> covered_strings;
    
    for(map<string, method_desc>::const_iterator iter_methods = this->methods_name2desc.begin(); iter_methods != this->methods_name2desc.end(); ++iter_methods){
        if(classes.count(iter_methods->second.class_name) > 0){
            for(vector<pair<ref_type, string>>::const_iterator iter_meth_all_refs = iter_methods->second.meth_all_refs.begin(); iter_meth_all_refs != iter_methods->second.meth_all_refs.end(); ++iter_meth_all_refs){
                
                if(!only_cfstring || (only_cfstring && iter_meth_all_refs->first == CFSTRING_REF)){
                    if(iter_meth_all_refs->second.length() > min_len){
                        covered_strings.insert(iter_meth_all_refs->second);
                    }
                }
            }
        }
    }
    
    return covered_strings;
}
