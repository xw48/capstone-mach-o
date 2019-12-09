//
//  parse_mach.cpp
//  Capstone
//
//  Created by xw on 15/7/6.
//
//

#include "parse_mach.h"
#include "../cs_priv.h"

#define switch_endian_32(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)&0xff0000)>>8)|(((x)&0xff000000)>>24))

/*
 definition borrowed from llvm/Support/MachO.h
 */
enum CPUSubTypeARM {
    CPU_SUBTYPE_ARM_ALL     = 0,
    CPU_SUBTYPE_ARM_V4T     = 5,
    CPU_SUBTYPE_ARM_V6      = 6,
    CPU_SUBTYPE_ARM_V5      = 7,
    CPU_SUBTYPE_ARM_V5TEJ   = 7,
    CPU_SUBTYPE_ARM_XSCALE  = 8,
    CPU_SUBTYPE_ARM_V7      = 9,
    //  unused  ARM_V7F     = 10,
    CPU_SUBTYPE_ARM_V7S     = 11,
    CPU_SUBTYPE_ARM_V7K     = 12,
    CPU_SUBTYPE_ARM_V6M     = 14,
    CPU_SUBTYPE_ARM_V7M     = 15,
    CPU_SUBTYPE_ARM_V7EM    = 16
};

enum CPUSubTypeARM64 {
    CPU_SUBTYPE_ARM64_ALL   = 0
};

enum : uint32_t {
    // Capability bits used in the definition of cpu_type.
    CPU_ARCH_MASK  = 0xff000000,   // Mask for architecture bits
    CPU_ARCH_ABI64 = 0x01000000    // 64 bit ABI
};

// Constants for the cputype field.
enum CPUType {
    CPU_TYPE_ANY       = -1,
    CPU_TYPE_X86       = 7,
    CPU_TYPE_I386      = CPU_TYPE_X86,
    CPU_TYPE_X86_64    = CPU_TYPE_X86 | CPU_ARCH_ABI64,
    /* CPU_TYPE_MIPS      = 8, */
    CPU_TYPE_MC98000   = 10, // Old Motorola PowerPC
    CPU_TYPE_ARM       = 12,
    CPU_TYPE_ARM64     = CPU_TYPE_ARM | CPU_ARCH_ABI64,
    CPU_TYPE_SPARC     = 14,
    CPU_TYPE_POWERPC   = 18,
    CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64
};

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

static bool is_http(string url) {
    if (url.find("http://") == 0 || url.find("https://") == 0) {
        return true;
    }
    return false;
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

static size_t get_class_finger(const class_block& blk) {
    set<string> class_content;
    class_content.insert(blk.class_name);
    for (vector<method_block>::const_iterator iter_methods = blk.class_or_instance_methods.begin(); iter_methods != blk.class_or_instance_methods.end(); ++iter_methods) {
        class_content.insert(iter_methods->method_name);
    }
    
    for (vector<pair<string, string>>::const_iterator iter_ivar = blk.instance_variables.begin(); iter_ivar != blk.instance_variables.end(); ++iter_ivar) {
        class_content.insert(iter_ivar->first);
    }
    
    size_t class_fingerprint = set_fingerprint(class_content);
    return class_fingerprint;
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
 Mach-O file always supports multi-architectures. Here we extract 32bit one and replace original file.
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
            cpu_type_t type = switch_endian_32(archs[idx].cputype);
            if (type == CPU_TYPE_ARM) {
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
                cout << "extracting thin mach-o for cpu " << type << ":" << subtype << endl;
                
                ofstream ofs(file_path, ios::trunc);
                ofs.write(buffer, size);
                ofs.close();
                
                delete [] buffer;
                break;
            }
        }
        delete [] archs;
    }
    ifs.close();
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
    if(this->file_len <= 0 || this->file_buffer == NULL){
        cout << "file not properly read into memory!" << endl;
        return -1;
    }
    
    size_t file_cursor = 0;
    this->idx_mach_header = file_cursor;
    file_cursor += (sizeof(struct mach_header));
    assert(file_cursor < this->file_len);
    
    /*
     enumerate on all load cmds
     */
    for (int load_seg_idx = 0; load_seg_idx < ((struct mach_header*)(this->file_buffer + this->idx_mach_header))->ncmds; ++load_seg_idx) {
        assert(file_cursor < this->file_len);
        
        struct load_command* load_cmd;
        load_cmd = reinterpret_cast<struct load_command*>(this->file_buffer + file_cursor);
        
        switch(load_cmd->cmd) {
            case LC_SYMTAB:{
                this->idx_symtab_cmd = file_cursor;
                file_cursor += load_cmd->cmdsize;
            }
                break;
            case LC_DYSYMTAB:{
                this->idx_dysymtab_cmd = file_cursor;
                file_cursor += load_cmd->cmdsize;
            }
                break;
            case LC_SEGMENT:{
                struct segment_command* cur_load_seg = reinterpret_cast<struct segment_command*>(this->file_buffer+file_cursor);
                
                struct segment_command seg_copy;
                memcpy(&seg_copy, cur_load_seg, sizeof(struct segment_command));
                this->segs.push_back(seg_copy);
                
                string segname(cur_load_seg->segname);
                if (segname.compare("__TEXT")) {
                    this->idx_text_seg = file_cursor;
                }
                if (segname.compare("__DATA")) {
                    this->idx_data_seg = file_cursor;
                }
                
                file_cursor += sizeof(struct segment_command);
                assert(file_cursor < this->file_len);
                
                for(int sect_idx = 0; sect_idx < cur_load_seg->nsects; ++sect_idx) {
                    struct section* sect = reinterpret_cast<struct section*>(this->file_buffer+file_cursor);
                    string sectname(sect->sectname);
                    
                    size_t pos__seg = sectname.find(segname);
                    if(pos__seg != string::npos){
                        sectname = sectname.substr(0, pos__seg);
                    }
                    
                    if (this->sections.find(sectname) != this->sections.end()) {
                        this->sections.insert(make_pair(sectname + segname, file_cursor));
                    } else {
                        this->sections.insert(make_pair(sectname, file_cursor));
                    }
                    
                    file_cursor += sizeof(struct section);
                    assert(file_cursor < this->file_len);
                }
            }
                break;
            case LC_DYLD_INFO_ONLY:{
                this->idx_dyld_info_cmd = file_cursor;
                file_cursor += load_cmd->cmdsize;
            }
                break;
            default:
                file_cursor += load_cmd->cmdsize;
                break;
        }
    }
    
    return 0;
}

void mach_desc::init_section_ptr() {
    map<string, size_t>::const_iterator it;
    unsigned char *file_end = (unsigned char*)(this->file_buffer+this->file_len);
    
    it = this->sections.find("__objc_classlist");
    if (it == this->sections.end()) {
        this->sec_classlist_ptr = NULL;
        this->buffer_classlist_ptr = NULL;
        this->classlist_count = 0;
    } else {
        this->sec_classlist_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_classlist_ptr = reinterpret_cast<uint32_t*>(this->file_buffer + this->sec_classlist_ptr->offset);
        this->classlist_count = this->sec_classlist_ptr->size/sizeof(uint32_t);
    }
    
    it = this->sections.find("__cstring");
    if (it == this->sections.end()) {
        this->sec_cstring_ptr = NULL;
        this->buffer_cstring_ptr = NULL;
    } else {
        this->sec_cstring_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_cstring_ptr = this->file_buffer+this->sec_cstring_ptr->offset;
    }
    
    it = this->sections.find("__ustring");
    if (it != this->sections.end()) {
        this->sec_ustring_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_ustring_ptr = this->file_buffer+this->sec_ustring_ptr->offset;
    } else {
        this->sec_ustring_ptr = NULL;
        this->buffer_ustring_ptr = NULL;
    }
    
    it = this->sections.find("__data");
    if (it != this->sections.end()) {
        this->sec_bare_data_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_bare_data_ptr = this->file_buffer+this->sec_bare_data_ptr->offset;
    } else {
        this->sec_bare_data_ptr = NULL;
        this->buffer_bare_data_ptr = NULL;
    }
    
    it = this->sections.find("__objc_data");
    if (it != this->sections.end()) {
        this->sec_data_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_data_ptr = this->file_buffer + this->sec_data_ptr->offset;
    } else {
        this->sec_data_ptr = NULL;
        this->buffer_data_ptr = NULL;
    }
    
    it = this->sections.find("__objc_const");
    if (it != this->sections.end()) {
        this->sec_objc_const_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_objc_const_ptr = this->file_buffer + this->sec_objc_const_ptr->offset;
    } else {
        this->sec_objc_const_ptr = NULL;
        this->buffer_objc_const_ptr = NULL;
    }
    
    it = this->sections.find("__const__DATA");
    if (it == this->sections.end()) {
        it = it = this->sections.find("__const");
    }
    
    if (it != this->sections.end()) {
        this->sec_data_const_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_data_const_ptr = reinterpret_cast<unsigned char*>(this->file_buffer + this->sec_data_const_ptr->offset);
    } else {
        this->sec_data_const_ptr = NULL;
        this->buffer_data_const_ptr = NULL;
    }
    
    it = this->sections.find("__objc_classname");
    if(it == this->sections.end()){
        cout << "__objc_classname not found, use cstring" << endl;
        this->sec_classname_ptr = this->sec_cstring_ptr;
        this->buffer_classname_ptr = this->buffer_cstring_ptr;
    }else{
        this->sec_classname_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_classname_ptr = this->file_buffer + this->sec_classname_ptr->offset;
        assert(this->buffer_classname_ptr < file_end);
    }
    
    it = this->sections.find("__objc_methname");
    if(it == this->sections.end()){
        cout << "__objc_methname not found, use cstring" << endl;
        this->sec_methname_ptr = this->sec_cstring_ptr;
        this->buffer_methname_ptr = this->buffer_cstring_ptr;
    }else{
        this->sec_methname_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_methname_ptr = this->file_buffer + this->sec_methname_ptr->offset;
        assert(buffer_methname_ptr < file_end);
    }
    
    it = this->sections.find("__objc_methtype");
    if(it == this->sections.end()){
        cout << "__objc_methtype not found, use cstring" << endl;
        this->sec_methtype_ptr = this->sec_cstring_ptr;
        this->buffer_methtype_ptr = this->buffer_cstring_ptr;
    }else{
        this->sec_methtype_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_methtype_ptr = this->file_buffer + this->sec_methtype_ptr->offset;
        assert(this->buffer_methtype_ptr < file_end);
    }
    
    it = this->sections.find("__objc_selrefs");
    if (it != this->sections.end()) {
        this->sec_selrefs_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_selrefs_ptr = reinterpret_cast<uint32_t*>(this->file_buffer + this->sec_selrefs_ptr->offset);
        this->selref_count = this->sec_selrefs_ptr->size/sizeof(uint32_t);
    } else {
        this->sec_selrefs_ptr = NULL;
        this->buffer_selrefs_ptr = NULL;
        this->selref_count = 0;
    }
    
    it = this->sections.find("__objc_classrefs");
    if(it != this->sections.end()){
        this->sec_classrefs_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_classrefs_ptr = reinterpret_cast<uint32_t*>(this->file_buffer+this->sec_classrefs_ptr->offset);
        this->classref_count = this->sec_classrefs_ptr->size/(sizeof(uint32_t)/sizeof(unsigned char));
    } else {
        this->sec_classrefs_ptr = NULL;
        this->buffer_classrefs_ptr = NULL;
        this->classref_count = 0;
    }
    
    it = this->sections.find("__objc_superrefs");
    if(it != this->sections.end()){
        this->sec_superrefs_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_superrefs_ptr = reinterpret_cast<uint32_t*>(this->file_buffer+this->sec_superrefs_ptr->offset);
        this->superref_count = this->sec_superrefs_ptr->size/(sizeof(uint32_t)/sizeof(unsigned char));
    } else {
        this->sec_superrefs_ptr = NULL;
        this->buffer_superrefs_ptr = NULL;
        this->superref_count = 0;
    }
    
    it = this->sections.find("__cfstring");
    if(it != this->sections.end()){
        this->sec_cfstring_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_cfstring_ptr = reinterpret_cast<cfstring_item*>(this->file_buffer+this->sec_cfstring_ptr->offset);
    } else {
        this->sec_cfstring_ptr = NULL;
        this->buffer_cfstring_ptr = NULL;
    }
    
    it = this->sections.find("__nl_symbol_ptr");
    if (it == this->sections.end()) {
        this->sec_nl_symbol_ptr = NULL;
        this->buffer_nl_symbol_ptr = NULL;
    } else {
        this->sec_nl_symbol_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
        this->buffer_nl_symbol_ptr = reinterpret_cast<nl_symbol_item*>(this->file_buffer+this->sec_nl_symbol_ptr->offset);
    }
    
    it = this->sections.find("__picsymbolstub4");
    if (it == this->sections.end()) {
        it = this->sections.find("__symbolstub1");
    }
    if (it == this->sections.end()) {
        it = this->sections.find("__symbol_stub4");
    }
    if(it != this->sections.end()) {
        this->sec_stub_ptr = reinterpret_cast<struct section*>(this->file_buffer+it->second);
    } else {
        this->sec_stub_ptr = NULL;
    }
}

/*
 try best to parse class structure, return class_block pointer
 try its best to parse class structure
 */
class_block* mach_desc::parse_class_item(class_item& cls_item) {
    if (cls_item.class_data < sec_objc_const_ptr->addr || cls_item.class_data > (sec_objc_const_ptr->addr + sec_objc_const_ptr->size)) {
        return NULL;
    }
    
    class_data cls_data;
    memcpy(&cls_data, buffer_objc_const_ptr+(cls_item.class_data - sec_objc_const_ptr->addr), sizeof(class_data));
    if(cls_data.class_name < sec_classname_ptr->addr || cls_data.class_name > (sec_classname_ptr->addr + sec_classname_ptr->size)){
        return NULL;
    }
    string cls_name(reinterpret_cast<const char*>(buffer_classname_ptr + (cls_data.class_name - sec_classname_ptr->addr)));
    this->derived_refs.insert(make_pair(cls_data.class_name, make_pair(CLASS_REF, cls_name)));
    
    map<string, class_block>::iterator iter_classes = this->class_blks.find(cls_name);
    if (iter_classes == this->class_blks.end()) {
        class_block m_block;
        m_block.class_name = cls_name;
        class_blks.insert(make_pair(cls_name, m_block));
        
        iter_classes = this->class_blks.find(cls_name);
        if (iter_classes == this->class_blks.end()) {
            return NULL;
        }
    }
    
    if (cls_data.methods != 0) {
        methods_in_class methods_in_cls;
        memcpy(&methods_in_cls, buffer_objc_const_ptr+(cls_data.methods - sec_objc_const_ptr->addr), sizeof(uint32_t)*2);
        
        if(methods_in_cls.method_count > 0){
            methods_in_cls.methods = new method_item[methods_in_cls.method_count];
            if(methods_in_cls.methods == NULL){
                cout << "Allocation methods_in_cls.methods ERR" << endl;
                return NULL;
            }
            
            memcpy(methods_in_cls.methods, buffer_objc_const_ptr+(cls_data.methods - sec_objc_const_ptr->addr)+sizeof(uint32_t)*2, methods_in_cls.method_count*sizeof(method_item));
            
            for(int idx = 0; idx < methods_in_cls.method_count; idx++){
                method_block meth_blk;
                meth_blk.class_name = cls_name;
                meth_blk.method_addr = (methods_in_cls.methods[idx].method_addr_plus_one/sizeof(uint32_t))*sizeof(uint32_t);
                
                uint32_t meth_name_addr = methods_in_cls.methods[idx].method_name;
                map<uint32_t, pair<REF_TYPE, string>>::const_iterator iter = this->derived_refs.find(meth_name_addr);
                if (iter != this->derived_refs.end()) {
                    meth_blk.method_name.append(iter->second.second);
                } else {
                    // if reference not found in method name, parse it here
                    if (meth_name_addr >= this->sec_methname_ptr->addr && meth_name_addr < (this->sec_methname_ptr->addr + this->sec_methname_ptr->size)) {
                        string parsed_method_name(reinterpret_cast<const char*>(this->buffer_methname_ptr + (meth_name_addr - this->sec_methname_ptr->addr)));
                        meth_blk.method_name.append(parsed_method_name);
                        this->derived_refs.insert(make_pair(meth_name_addr, make_pair(SEL_REF, parsed_method_name)));
                    }
                }
                
                iter_classes->second.class_or_instance_methods.push_back(meth_blk);
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
        memcpy(&prot_cnt, buffer_objc_const_ptr+(cur_prot - sec_objc_const_ptr->addr), sizeof(uint32_t));
        if(prot_cnt > 0){
            uint32_t* prot_list = new uint32_t[prot_cnt];
            if(prot_list == NULL){
                cout << "Allocation prot_list ERR" << endl;
                return NULL;
            }
            memcpy(prot_list, buffer_objc_const_ptr+(cur_prot - sec_objc_const_ptr->addr)+sizeof(uint32_t), prot_cnt*sizeof(uint32_t));
            
            for(int idx = 0; idx < prot_cnt; ++idx){
                if(prot_list[idx] >= sec_bare_data_ptr->addr && prot_list[idx] < (sec_bare_data_ptr->addr+sec_bare_data_ptr->size)){
                    prot_item prot_struct;
                    memcpy(&prot_struct, buffer_bare_data_ptr+(prot_list[idx]-sec_bare_data_ptr->addr), sizeof(prot_item));
                    
                    if(prot_struct.name_ptr >= sec_classname_ptr->addr && prot_struct.name_ptr < (sec_classname_ptr->addr+sec_classname_ptr->size)){
                        string prot_name((char*)(buffer_classname_ptr+(prot_struct.name_ptr-sec_classname_ptr->addr)));
                        iter_classes->second.protos.insert(prot_name);
                    }
                    
                    if(prot_struct.sub_prots > 0){
                        proto_queue.push(prot_struct.sub_prots);
                    }
                }
            }
            delete [] prot_list;
        }
    }
    
    if (cls_data.properties != 0) {
        uint32_t prop_size_and_count[2];
        memcpy(prop_size_and_count, buffer_objc_const_ptr + cls_data.properties - sec_objc_const_ptr->addr, 2*sizeof(uint32_t));
        
        if (prop_size_and_count[0] == sizeof(prop_item) && prop_size_and_count[1] > 0) {
            prop_item* prop_items = new prop_item[prop_size_and_count[1]];
            if (prop_items == NULL) {
                cout << "Allocation prop_items ERR" << endl;
                return NULL;
            }
            
            memcpy(prop_items, buffer_objc_const_ptr + cls_data.properties - sec_objc_const_ptr->addr + 2*sizeof(uint32_t), prop_size_and_count[1]*sizeof(prop_item));
            for (int idx = 0; idx < prop_size_and_count[1]; ++idx) {
                if (prop_items[idx].prop_name < sec_cstring_ptr->addr || prop_items[idx].prop_name > (sec_cstring_ptr->addr + sec_cstring_ptr->size) || prop_items[idx].prop_type < sec_cstring_ptr->addr || prop_items[idx].prop_type > (sec_cstring_ptr->addr + sec_cstring_ptr->size)) {
                    continue;
                }
                
                const char* prop_name_ptr = reinterpret_cast<const char*>(buffer_cstring_ptr + (prop_items[idx].prop_name - sec_cstring_ptr->addr));
                const char* prop_type_ptr = reinterpret_cast<const char*>(buffer_cstring_ptr + (prop_items[idx].prop_type - sec_cstring_ptr->addr));
                const char* file_boundary = reinterpret_cast<const char*>(this->file_buffer+this->file_len);
                if (prop_name_ptr > file_boundary || prop_type_ptr > file_boundary || prop_name_ptr < reinterpret_cast<const char*>(this->file_buffer) || prop_type_ptr < reinterpret_cast<const char*>(this->file_buffer)) {
                    continue;
                }
                
                string prop_name(prop_name_ptr);
                string prop_type(prop_type_ptr);
                iter_classes->second.props.push_back(make_pair(prop_name, prop_type));
            }
        }
    }
    
    
    if(cls_data.instance_variables != 0){
        uint32_t ivar_size_and_count[2];
        memcpy(ivar_size_and_count, buffer_objc_const_ptr + cls_data.instance_variables - sec_objc_const_ptr->addr, 2*sizeof(uint32_t));
        
        if(ivar_size_and_count[0] == sizeof(ivar_item) && ivar_size_and_count[1] > 0){
            ivar_item* ivar_items = new ivar_item[ivar_size_and_count[1]];
            if(ivar_items == NULL){
                cout << "Allocation ivar_items ERR" << endl;
                return NULL;
            }
            memcpy(ivar_items, buffer_objc_const_ptr + cls_data.instance_variables - sec_objc_const_ptr->addr + 2*sizeof(uint32_t), ivar_size_and_count[1]*sizeof(ivar_item));
            
            for(int idx = 0; idx < ivar_size_and_count[1]; idx++){
                if(ivar_items[idx].ivar_name < sec_methname_ptr->addr || ivar_items[idx].ivar_name > (sec_methname_ptr->size + sec_methname_ptr->addr) || ivar_items[idx].ivar_type < sec_methtype_ptr->addr || ivar_items[idx].ivar_type > (sec_methtype_ptr->size + sec_methtype_ptr->addr)){
                    continue;
                }
                const char* file_boundary = reinterpret_cast<const char*>(this->file_buffer+this->file_len);
                const char* sel_name_ptr = reinterpret_cast<const char*>(buffer_methname_ptr + (ivar_items[idx].ivar_name-sec_methname_ptr->addr));
                
                const char* sel_type_ptr = reinterpret_cast<const char*>(buffer_methtype_ptr + (ivar_items[idx].ivar_type-sec_methtype_ptr->addr));
                if (sel_type_ptr > file_boundary || sel_name_ptr > file_boundary || sel_type_ptr < reinterpret_cast<const char*>(this->file_buffer) || sel_name_ptr < reinterpret_cast<const char*>(this->file_buffer)) {
                    continue;
                }
                
                string ivar_name(sel_name_ptr);
                string ivar_type(sel_type_ptr);
                iter_classes->second.instance_variables.push_back(make_pair(ivar_name, ivar_type));
                
                //log ivar as AdMoGoInterstitial.configKey(@"NSString")
                string ivar_full(cls_name);
                ivar_full.append(".");
                ivar_full.append(ivar_name);
                ivar_full.append("(");
                ivar_full.append(ivar_type);
                ivar_full.append(")");
                this->derived_refs.insert(make_pair(ivar_items[idx].ivar_ref, pair<REF_TYPE, string>(IVAR_REF, ivar_full)));
            }
            delete[] ivar_items;
        }
    }
    
    
    return &(iter_classes->second);
}

void mach_desc::extract_virtual_refs() {
    //bind info https://opensource.apple.com/source/dyld/dyld-195.5/src/ImageLoaderMachOCompressed.cpp
    if(this->idx_dyld_info_cmd < this->file_len && this->idx_dyld_info_cmd > 0){
        struct dyld_info_command* dyld_info_ptr = reinterpret_cast<struct dyld_info_command*>(this->file_buffer+this->idx_dyld_info_cmd);
        try{
            uint8_t type = 0;
            int segmentIndex = 0;
            uintptr_t address = this->segs.at(0).vmaddr;
            uintptr_t segmentEndAddress = this->segs.at(0).vmaddr + this->segs.at(0).vmsize;
            const char* symbolName = NULL;
            uint8_t symboFlags = 0;
            uintptr_t libraryOrdinal = 0;
            intptr_t addend = 0;
            uintptr_t count;
            uintptr_t skip;
            const uint8_t* const start = this->file_buffer+dyld_info_ptr->bind_off;
            const uint8_t* const end = start+dyld_info_ptr->bind_size;
            const uint8_t* p = start;
            bool done = false;
            
            while(!done && p < end){
                uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
                uint8_t opcode = *p & BIND_OPCODE_MASK;
                ++p;
                
                switch(opcode){
                    case BIND_OPCODE_DONE:
                        done = true;
                        break;
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                        libraryOrdinal = immediate;
                        break;
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                        libraryOrdinal = read_uleb128(p, end);
                        break;
                    case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                        if ( immediate == 0 )
                            libraryOrdinal = 0;
                        else {
                            int8_t signExtended = BIND_OPCODE_MASK | immediate;
                            libraryOrdinal = signExtended;
                        }
                        break;
                    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                        symbolName = (char*)p;
                        symboFlags = immediate;
                        while (*p != '\0')
                            ++p;
                        ++p;
                        break;
                    case BIND_OPCODE_SET_TYPE_IMM:
                        type = immediate;
                        break;
                    case BIND_OPCODE_SET_ADDEND_SLEB:
                        addend = read_sleb128(p, end);
                        break;
                    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:{
                        segmentIndex = immediate;
                        if (segmentIndex > this->segs.size()) {
                            throw "Bad Offset";
                        }
                        address = this->segs.at(segmentIndex).vmaddr + read_uleb128(p, end);
                        segmentEndAddress = this->segs.at(segmentIndex).vmaddr + this->segs.at(segmentIndex).vmsize;
                    }
                        break;
                    case BIND_OPCODE_ADD_ADDR_ULEB:
                        address += read_uleb128(p, end);
                        break;
                    case BIND_OPCODE_DO_BIND:
                        if (address >= segmentEndAddress) {
                            throw "Bad Offset";
                        }
                        this->virtual_refs.insert(make_pair(address, symbolName));
                        address += sizeof(uint32_t);
                        break;
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                        if (address >= segmentEndAddress) {
                            throw "Bad Offset";
                        }
                        this->virtual_refs.insert(make_pair(address, symbolName));
                        address += read_uleb128(p, end) + sizeof(uint32_t);
                        break;
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                        if ( address >= segmentEndAddress ){
                            throw "Bad Offset";
                        }
                        this->virtual_refs.insert(make_pair(address, symbolName));
                        address += immediate*sizeof(uint32_t) + sizeof(uint32_t);
                        break;
                    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                        count = read_uleb128(p, end);
                        skip = read_uleb128(p, end);
                        for (uint32_t i=0; i < count; ++i) {
                            if ( address >= segmentEndAddress ){
                                throw "Bad Offset";
                            }
                            
                            this->virtual_refs.insert(make_pair(address, symbolName));
                            address += skip + sizeof(uint32_t);
                        }
                        break;
                    default:
                        cout << "bad bind opcode %d in bind info" << endl;
                }
            }} catch (const char* msg) {
                cout << "Error: " << msg << endl;
            }
    }else{
        cout << "LC_DYLD_INFO_ONLY segment not found" << endl;
    }
    
    //lazy bind info
    if(this->idx_dyld_info_cmd < this->file_len && this->idx_dyld_info_cmd > 0){
        struct dyld_info_command* dyld_info_ptr = reinterpret_cast<struct dyld_info_command*>(this->file_buffer+this->idx_dyld_info_cmd);
        
        try{
            uint8_t type = BIND_TYPE_POINTER;
            int segmentIndex = 0;
            uintptr_t address = this->segs.at(0).vmaddr;
            uintptr_t segmentEndAddress = this->segs.at(0).vmaddr + this->segs.at(0).vmsize;
            const char* symbolName = NULL;
            uint8_t symboFlags = 0;
            uintptr_t libraryOrdinal = 0;
            intptr_t addend = 0;
            const uint8_t* const start = this->file_buffer+dyld_info_ptr->lazy_bind_off;
            const uint8_t* const end = start+dyld_info_ptr->lazy_bind_size;
            const uint8_t* p = start;
            bool done = false;
            
            while(!done && p < end){
                uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
                uint8_t opcode = *p & BIND_OPCODE_MASK;
                ++p;
                
                switch(opcode){
                    case BIND_OPCODE_DONE:
                        break;
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                        libraryOrdinal = immediate;
                        break;
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                        libraryOrdinal = read_uleb128(p, end);
                        break;
                    case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                        if ( immediate == 0 )
                            libraryOrdinal = 0;
                        else {
                            int8_t signExtended = BIND_OPCODE_MASK | immediate;
                            libraryOrdinal = signExtended;
                        }
                        break;
                    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                        symbolName = (char*)p;
                        symboFlags = immediate;
                        while (*p != '\0')
                            ++p;
                        ++p;
                        break;
                    case BIND_OPCODE_SET_TYPE_IMM:
                        type = immediate;
                        break;
                    case BIND_OPCODE_SET_ADDEND_SLEB:
                        addend = read_sleb128(p, end);
                        break;
                    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:{
                        segmentIndex = immediate;
                        if (segmentIndex > this->segs.size()) {
                            throw "Bad Offset";
                        }
                        address = this->segs.at(segmentIndex).vmaddr + read_uleb128(p, end);
                        segmentEndAddress = this->segs.at(segmentIndex).vmaddr + this->segs.at(segmentIndex).vmsize;
                    }
                        break;
                    case BIND_OPCODE_ADD_ADDR_ULEB:
                        address += read_uleb128(p, end);
                        break;
                    case BIND_OPCODE_DO_BIND:
                        if (address >= segmentEndAddress) {
                            throw "Bad Offset";
                        }
                        this->virtual_refs.insert(make_pair(address, symbolName));
                        address += sizeof(uint32_t);
                        break;
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                    default:
                        cout << "bad bind opcode %d in bind info" << endl;
                }
            }} catch (const char* msg) {
                cout << "Error: " << msg << endl;
            }
    }else{
        cout << "LC_DYLD_INFO_ONLY segment not found" << endl;
    }
    
    //weak bind info
    if(this->idx_dyld_info_cmd < this->file_len && this->idx_dyld_info_cmd > 0){
        struct dyld_info_command* dyld_info_ptr = reinterpret_cast<struct dyld_info_command*>(this->file_buffer+this->idx_dyld_info_cmd);
        
        try{
            uint8_t type = 0;
            int segmentIndex = 0;
            uintptr_t address = this->segs.at(0).vmaddr;
            uintptr_t segmentEndAddress = this->segs.at(0).vmaddr + this->segs.at(0).vmsize;
            const char* symbolName = NULL;
            uint8_t symboFlags = 0;
            uintptr_t libraryOrdinal = 0;
            intptr_t addend = 0;
            uintptr_t count;
            uintptr_t skip;
            const uint8_t* const start = this->file_buffer+dyld_info_ptr->weak_bind_off;
            const uint8_t* const end = start+dyld_info_ptr->weak_bind_size;
            const uint8_t* p = start;
            bool done = false;
            
            while(!done && p < end){
                uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
                uint8_t opcode = *p & BIND_OPCODE_MASK;
                ++p;
                
                switch(opcode){
                    case BIND_OPCODE_DONE:
                        done = true;
                        break;
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                        libraryOrdinal = immediate;
                        break;
                    case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                        libraryOrdinal = read_uleb128(p, end);
                        break;
                    case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                        if ( immediate == 0 )
                            libraryOrdinal = 0;
                        else {
                            int8_t signExtended = BIND_OPCODE_MASK | immediate;
                            libraryOrdinal = signExtended;
                        }
                        break;
                    case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                        symbolName = (char*)p;
                        symboFlags = immediate;
                        while (*p != '\0')
                            ++p;
                        ++p;
                        break;
                    case BIND_OPCODE_SET_TYPE_IMM:
                        type = immediate;
                        break;
                    case BIND_OPCODE_SET_ADDEND_SLEB:
                        addend = read_sleb128(p, end);
                        break;
                    case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:{
                        segmentIndex = immediate;
                        if (segmentIndex > this->segs.size()) {
                            throw "Bad Offset";
                        }
                        address = this->segs.at(segmentIndex).vmaddr + read_uleb128(p, end);
                        segmentEndAddress = this->segs.at(segmentIndex).vmaddr + this->segs.at(segmentIndex).vmsize;
                    }
                        break;
                    case BIND_OPCODE_ADD_ADDR_ULEB:
                        address += read_uleb128(p, end);
                        break;
                    case BIND_OPCODE_DO_BIND:
                        if (address >= segmentEndAddress) {
                            throw "Bad Offset";
                        }
                        this->virtual_refs.insert(make_pair(address, symbolName));
                        address += sizeof(uint32_t);
                        break;
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                        if (address >= segmentEndAddress) {
                            throw "Bad Offset";
                        }
                        this->virtual_refs.insert(make_pair(address, symbolName));
                        address += read_uleb128(p, end) + sizeof(uint32_t);
                        break;
                    case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                        if ( address >= segmentEndAddress ){
                            throw "Bad Offset";
                        }
                        this->virtual_refs.insert(make_pair(address, symbolName));
                        address += immediate*sizeof(uint32_t) + sizeof(uint32_t);
                        break;
                    case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                        count = read_uleb128(p, end);
                        skip = read_uleb128(p, end);
                        for (uint32_t i=0; i < count; ++i) {
                            if ( address >= segmentEndAddress ){
                                throw "Bad Offset";
                            }
                            
                            this->virtual_refs.insert(make_pair(address, symbolName));
                            address += skip + sizeof(uint32_t);
                        }
                        break;
                    default:
                        cout << "bad bind opcode %d in bind info" << endl;
                }
            }} catch (const char* msg) {
                cout << "Error: " << msg << endl;
            }
    }else{
        cout << "LC_DYLD_INFO_ONLY segment not found" << endl;
    }
}

void mach_desc::extract_base_refs() {
    //bind info
    extract_virtual_refs();
    
    //selector/method names
    uint32_t selref_base_addr = sec_selrefs_ptr->addr;
    for (int idx = 0; idx < selref_count; ++idx) {
        if(buffer_selrefs_ptr[idx] >= sec_methname_ptr->addr && buffer_selrefs_ptr[idx] < (sec_methname_ptr->addr+sec_methname_ptr->size)){
            uint32_t selref_addr = selref_base_addr + idx*sizeof(uint32_t);
            uint32_t meth_name_addr = buffer_selrefs_ptr[idx];
            string name((reinterpret_cast<const char*>(buffer_methname_ptr+buffer_selrefs_ptr[idx]-sec_methname_ptr->addr)));
            this->derived_refs.insert(make_pair(selref_addr, make_pair(SEL_REF, name)));
            this->derived_refs.insert(make_pair(meth_name_addr, make_pair(SEL_REF, name)));
        }
    }
    
    //strings
    uint32_t cfstring_start = sec_cfstring_ptr->addr;
    uint32_t cstring_start = sec_cstring_ptr->addr;
    uint32_t cstring_end = sec_cstring_ptr->addr + sec_cstring_ptr->size;
    uint32_t ustring_start = 0;
    uint32_t ustring_end = 0;
    if (sec_ustring_ptr != NULL) {
        ustring_start = sec_ustring_ptr->addr;
        ustring_end = sec_ustring_ptr->addr + sec_ustring_ptr->size;
    }
    
    for (int idx = 0; idx < sec_cfstring_ptr->size/sizeof(cfstring_item); ++idx) {
        uint32_t real_string_ref = buffer_cfstring_ptr[idx].cstring_ref;
        
        if (real_string_ref >= cstring_start && real_string_ref < cstring_end) {
            string cstr(reinterpret_cast<char*>(buffer_cstring_ptr+buffer_cfstring_ptr[idx].cstring_ref-sec_cstring_ptr->addr));
            this->derived_refs.insert(make_pair(cfstring_start + idx*sizeof(cfstring_item), make_pair(CFSTRING_REF, cstr)));
            this->derived_refs.insert(make_pair(real_string_ref, make_pair(CFSTRING_REF, cstr)));
        } else {
            if (this->sec_ustring_ptr == NULL || this->buffer_ustring_ptr == NULL) {
                continue;
            }
            
            if (real_string_ref >= ustring_start && real_string_ref < ustring_end) {
                char16_t* ref = reinterpret_cast<char16_t*>(buffer_ustring_ptr+real_string_ref-sec_ustring_ptr->addr);
                u16string ref16 = u16string(ref);
                std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conv;
                
                this->derived_refs.insert(make_pair(cfstring_start+idx*sizeof(cfstring_item), make_pair(CFSTRING_REF, conv.to_bytes(ref16))));
                this->derived_refs.insert(make_pair(real_string_ref, make_pair(CFSTRING_REF, conv.to_bytes(ref16))));
            }
        }
    }
    
    //symbol table
    vector<string> symbols;
    struct symtab_command* symtab_ptr = reinterpret_cast<struct symtab_command*>(this->file_buffer+this->idx_symtab_cmd);
    struct nlist* buffer_symtab = reinterpret_cast<struct nlist*>(this->file_buffer+symtab_ptr->symoff);
    unsigned char* buffer_str = reinterpret_cast<unsigned char*>(this->file_buffer+symtab_ptr->stroff);
    uint32_t str_size = symtab_ptr->strsize;
    
    for(int idx = 0; idx < symtab_ptr->nsyms; idx++){
        uint32_t cur_size = buffer_symtab[idx].n_un.n_strx;
        if(cur_size > 0 && cur_size < str_size){
            string symbol_item(reinterpret_cast<const char*>(&(buffer_str[buffer_symtab[idx].n_un.n_strx])));
            symbols.push_back(symbol_item);
        }
    }
    
    //symbol stubs
    struct dysymtab_command* dysymtab_ptr = reinterpret_cast<struct dysymtab_command*>(this->file_buffer+this->idx_dysymtab_cmd);
    uint32_t* buffer_dysymtab = reinterpret_cast<uint32_t*>(this->file_buffer+dysymtab_ptr->indirectsymoff);
    if (sec_stub_ptr != NULL) {
        uint32_t addr_stub = sec_stub_ptr->addr;
        uint32_t sizeof_stub = (sec_stub_ptr->reserved2>0)?sec_stub_ptr->reserved2:16;
        uint32_t in_indref_off = (sec_stub_ptr->reserved1>0)?sec_stub_ptr->reserved1:0;
        
        if(this->idx_dysymtab_cmd > 0){
            for(uint32_t idx = 0; idx < sec_stub_ptr->size/sizeof_stub; idx++){
                uint32_t addr_stub4_item = addr_stub + idx*sizeof_stub;
                uint32_t idx_in_indref = idx + in_indref_off;
                
                if(idx_in_indref < dysymtab_ptr->nindirectsyms){
                    uint32_t idx_in_sym_tab = buffer_dysymtab[idx_in_indref];
                    if(idx_in_sym_tab > 0 && idx_in_sym_tab < symbols.size()){
                        this->derived_refs.insert(make_pair(addr_stub4_item, make_pair(SYMBOL_STUB_REF, symbols[idx_in_sym_tab])));
                    }
                }
            }
            
            //extracting external relocation info
            const struct relocation_info* const reloc_start = reinterpret_cast<struct relocation_info*>(this->file_buffer+dysymtab_ptr->extreloff);
            const struct relocation_info* const reloc_end = &reloc_start[dysymtab_ptr->nextrel];
            for(const struct relocation_info* reloc = reloc_start; reloc < reloc_end; reloc++){
                if((reloc->r_address & R_SCATTERED) == 0){
                    if(reloc->r_symbolnum == R_ABS){
                        /*ignore absolute relocations*/
                    }else if(reloc->r_length == RELOC_SIZE){
                        if(reloc->r_extern == 1 && reloc->r_type == GENERIC_RELOC_VANILLA){
                            if(reloc->r_symbolnum >= 0 && reloc->r_symbolnum < symbols.size()){
                                this->derived_refs.insert(make_pair(reloc->r_address, make_pair(RELOC_BIND_TYPE, symbols[reloc->r_symbolnum])));
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
    }
    
    //other part (those not dynamically binded) of non-lazy symbol table
    if (sec_nl_symbol_ptr != NULL) {
        uint32_t sizeof_nl_item = sizeof(nl_symbol_item);
        for (uint32_t idx = 0; idx < sec_nl_symbol_ptr->size/sizeof_nl_item; ++idx) {
            uint32_t addr_la_item = sec_nl_symbol_ptr->addr + idx*sizeof_nl_item;
            
            if (sec_data_const_ptr == NULL) {
                break;
            }
            
            if (this->virtual_refs.find(addr_la_item) != this->virtual_refs.end()) {
                continue;
            }
            
            uint32_t addr_const_sec = *(nl_symbol_item*)(buffer_nl_symbol_ptr + idx);
            if (addr_const_sec < sec_data_const_ptr->addr || addr_const_sec >= (sec_data_const_ptr->addr + sec_data_const_ptr->size)) {
                continue;
            }
            
            uint32_t addr_cfstring_sec = *(uint32_t*)(buffer_data_const_ptr + (addr_const_sec - sec_data_const_ptr->addr));
            map<uint32_t, pair<REF_TYPE, string>>::const_iterator iter = this->derived_refs.find(addr_cfstring_sec);
            if (iter != this->derived_refs.end()) {
                this->derived_refs.insert(make_pair(addr_const_sec, iter->second));
                this->derived_refs.insert(make_pair(addr_la_item, iter->second));
                //cout << iter->second.second << "\t\t" << hex << addr_la_item << "\t\t" << hex << addr_const_sec << endl;
            }
        }
    }
}

int mach_desc::extract_methods_and_refs(){
    if(this->file_buffer == NULL || this->file_len <= 0) {
        cout << "file not properly read into memory!" << endl;
        return -1;
    }
    
    this->init_section_ptr();
    this->extract_base_refs();
    
    set<long long> indexed_in_classlist;
    // parse classes indexed in classlist section
    for(int idx = 0; idx < classlist_count; ++idx) {
        uint32_t class_ref = buffer_classlist_ptr[idx];
        
        if (class_ref >= sec_data_ptr->addr && class_ref <= (sec_data_ptr->addr + sec_data_ptr->size)) {
            class_item cls_item;
            unsigned char* cls_item_addr = buffer_data_ptr+(class_ref-sec_data_ptr->addr);
            memcpy(&cls_item, cls_item_addr, sizeof(class_item));
            indexed_in_classlist.insert((long long)cls_item_addr);
            class_block* this_class_block = this->parse_class_item(cls_item);
            
            if (this_class_block != NULL) {
                if (cls_item.super_class >= sec_data_ptr->addr && cls_item.super_class < (sec_data_ptr->addr + sec_data_ptr->size)) {
                    this_class_block->super_class_addr = cls_item.super_class;
                } else {
                    this_class_block->super_class_addr = class_ref + offsetof(class_item, super_class);
                }
                
                this->addr_p2_class.insert(make_pair(class_ref, this_class_block));
                this->derived_refs.insert(make_pair(class_ref, make_pair(CLASS_REF, this_class_block->class_name)));
                
                //handle meta class
                if (cls_item.meta_class >= sec_data_ptr->addr && cls_item.meta_class <= (sec_data_ptr->addr + sec_data_ptr->size)) {
                    class_item meta_cls_item;
                    unsigned char* meta_cls_item_addr = buffer_data_ptr + (cls_item.meta_class - sec_data_ptr->addr);
                    memcpy(&meta_cls_item, meta_cls_item_addr, sizeof(class_item));
                    indexed_in_classlist.insert((long long)meta_cls_item_addr);
                    class_block* meta_class_block = this->parse_class_item(meta_cls_item);
                    if (meta_class_block != NULL) {
                        this->addr_p2_class.insert(make_pair(cls_item.meta_class, meta_class_block));
                        this->derived_refs.insert(make_pair(cls_item.meta_class, make_pair(CLASS_REF, meta_class_block->class_name)));
                    }
                }
            }
        }
    }
    
    // parse un-indexed classes
    unsigned char* class_data_begin = buffer_data_ptr;
    unsigned char* class_data_end = buffer_data_ptr + sec_data_ptr->size;
    unsigned char* class_data_idx = class_data_begin;
    
    while (class_data_idx + sizeof(class_item) < class_data_end ) {
        if(indexed_in_classlist.find((long long)class_data_idx) != indexed_in_classlist.end()) {
            class_data_idx += sizeof(class_item);
            continue;
        }
        
        long class_ref = sec_data_ptr->addr + class_data_idx - class_data_begin;
        
        class_item cls_item;
        memcpy(&cls_item, class_data_idx, sizeof(class_item));
        class_data_idx += sizeof(class_item);
        class_block* this_class_block = this->parse_class_item(cls_item);
        
        if (this_class_block != NULL) {
            if (cls_item.super_class >= sec_data_ptr->addr && cls_item.super_class < (sec_data_ptr->addr + sec_data_ptr->size)) {
                this_class_block->super_class_addr = cls_item.super_class;
            } else {
                this_class_block->super_class_addr = (uint32_t)class_ref + offsetof(class_item, super_class);
            }
            
            this->addr_p2_class.insert(make_pair(class_ref, this_class_block));
            this->derived_refs.insert(make_pair(class_ref, make_pair(CLASS_REF, this_class_block->class_name)));
        }
    }
    
    for(map<uint32_t, pair<REF_TYPE, string>>::const_iterator iter_class = this->derived_refs.begin(); iter_class != this->derived_refs.end(); ++iter_class) {
        if (iter_class->second.first != CLASS_REF) {
            continue;
        }
        if (iter_class->first < sec_data_ptr->addr || iter_class->first > (sec_data_ptr->addr + sec_data_ptr->size)) {
            continue;
        }
        
        if (std::find(this->class_def_order.begin(), this->class_def_order.end(), iter_class->second.second) == this->class_def_order.end()) {
            this->class_def_order.push_back(iter_class->second.second);
        }
    }
    
    for (map<uint32_t, class_block*>::iterator iter_classes = this->addr_p2_class.begin(); iter_classes != this->addr_p2_class.end(); ++iter_classes) {
        class_block* this_block = iter_classes->second;
        
        map<uint32_t, class_block*>::const_iterator iter = this->addr_p2_class.find(this_block->super_class_addr);
        if(iter == this->addr_p2_class.end()) {
            map<uint32_t, string>::const_iterator iter_virtual = this->virtual_refs.find(this_block->super_class_addr);
            if (iter_virtual != this->virtual_refs.end()) {
                this_block->super_class_name = iter_virtual->second;
                //cout << iter_virtual->second << "-->" << this_block->class_name << endl;
            }
        } else {
            this_block->super_class_name = iter->second->class_name;
            //cout << iter->second->class_name << "-->" << this_block->class_name << endl;
        }
    }
    
    /*
     add references in __objc_classrefs
     */
    if (sec_classrefs_ptr != NULL && buffer_classrefs_ptr != NULL) {
        uint32_t* begin = buffer_classrefs_ptr;
        uint32_t* end = (uint32_t*)((char*)buffer_classrefs_ptr + sec_classrefs_ptr->size);
        
        for (uint32_t* ptr = begin; ptr < end; ++ptr) {
            uint32_t addr = sec_classrefs_ptr->addr + (uint32_t)((char*)ptr-(char*)begin);
            map<uint32_t, pair<REF_TYPE, string>>::const_iterator iter_derived_refs = this->derived_refs.find(*ptr);
            
            if (iter_derived_refs != this->derived_refs.end()) {
                pair<REF_TYPE, string> ref = make_pair(iter_derived_refs->second.first, iter_derived_refs->second.second);
                this->derived_refs.insert(make_pair(addr, ref));
            }
        }
    }
    
    return 0;
}


/*
 disassemble all defined methods and extract detailed references.
 */
int mach_desc::disasm(){
    map<string, size_t>::const_iterator iter_section = this->sections.find("__text");
    if(iter_section == this->sections.end()){
        cout << "error __text section not found!" << endl;
        return -1;
    }
    sec_text_ptr = reinterpret_cast<struct section*>(this->file_buffer+iter_section->second);
    
    //most functions starts with instructions in test_instr_arr
    set<string> test_instr_set = {"push", "mov", "ldr", "cmp", "add", "movs", "movw", "movt", "blx", "ldr", "pop.w", "b.w"};
    
    map<uint32_t, string> method_addr_name;
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        for (vector<method_block>::iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin();
             iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            method_addr_name.insert(make_pair(iter_method->method_addr, iter_class_blk->first + ":" + iter_method->method_name));
        }
    }
    
    //enumerate on each method entry
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        uint32_t cstring_addr_start = sec_cstring_ptr->addr;
        uint32_t cstring_addr_end = sec_cstring_ptr->addr+sec_cstring_ptr->size;
        
        for (vector<method_block>::iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            
            uint32_t method_vm_addr = iter_method->method_addr;
            string method_class_name = iter_method->class_name;
            
            uint32_t next_method_addr = method_vm_addr + 0x8000;
            string next_method_class;
            map<uint32_t, string>::iterator iter_method_addr = method_addr_name.find(method_vm_addr);
            if (iter_method_addr != method_addr_name.end()) {
                ++iter_method_addr;
                if (iter_method_addr != method_addr_name.end()) {
                    next_method_addr = iter_method_addr->first;
                    next_method_class.append(iter_method_addr->second);
                }
            }
            
            //add extra class reference
            if (iter_class_blk->first.length() > 0) {
                iter_method->base_ref.push_back(make_pair(CLASS_REF, iter_class_blk->first));
            }
            
            //cout << iter_class_blk->first << ":" << iter_method->method_name << endl;
            
            //dissam function at method_code*/
            unsigned char* method_code = this->file_buffer + sec_text_ptr->offset + method_vm_addr - sec_text_ptr->addr;
            
            csh handle;
            cs_insn* insn;
            cs_err err;
            size_t count;
            
            //check ARM or Thumb
            uint32_t thumb_cnt = 0;
            uint32_t arm_cnt = 0;
            
            err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle);
            if (err) {
                cout << "Failed on cs_open() with error:" << err << endl;
                break;
            }
            cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
            count = cs_disasm(handle, method_code, 0x40, method_vm_addr, 0, &insn);
            if(count > 0){
                for (int idx = 0; idx < count; ++idx) {
                    if(test_instr_set.count(insn[idx].mnemonic) > 0) {
                        ++thumb_cnt;
                    }
                }
            }
            cs_free(insn, count);
            cs_close(&handle);
            
            err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
            if (err) {
                cout << "Failed on cs_open() with error:" << err << endl;
                break;
            }
            cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
            count = cs_disasm(handle, method_code, 0x40, method_vm_addr, 0, &insn);
            if(count > 0){
                for (int idx = 0; idx < count; ++idx) {
                    if(test_instr_set.count(insn[idx].mnemonic) > 0) {
                        ++arm_cnt;
                    }
                }
            }
            cs_free(insn, count);
            cs_close(&handle);
            
            bool is_ARM = (arm_cnt>thumb_cnt)?true:false;
            
            err = cs_open(CS_ARCH_ARM, is_ARM?CS_MODE_ARM:CS_MODE_THUMB, &handle);
            if (err) {
                cout << "Failed on cs_open() with error:" << err << endl;
                break;
            }
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
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
            set<string> jmp_out_instr = {"pop", "popeq", "pop.w"};
            //set<string> jmp_out_instr = {"b", "bx", "b.w"};
            set<string> add_instr = {"adc", "add"};
            
            /*
             If a named method is followed by some sub-procedure, ignore jump out instructions
             */
            bool ignore_jump_out = false;
            if (next_method_class.length() > 0 && method_class_name.length() > 0 && next_method_class.find(method_class_name) == 0) {
                ignore_jump_out = true;
            }
            
            if (count){
                for(int idx = 0; idx < count; idx++){
                    if(insn[idx].detail == NULL) {
                        continue;
                    }
                    
                    //cout << insn[idx].mnemonic << endl;
                    
                    cs_arm* arm = &(insn[idx].detail->arm);
                    if(mov_instr.count(insn[idx].mnemonic) > 0){
                        /*log move immediate value to register*/
                        if(arm->op_count >= 2 && arm->operands[0].type == ARM_OP_REG){
                            const char* reg_name = cs_reg_name(handle, arm->operands[0].reg);
                            int32_t imm_val = -1;
                            
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
                                    if(mem_addr >= sec_text_ptr->addr && mem_addr < (sec_text_ptr->addr + sec_text_ptr->size)){
                                        imm_val = *(uint32_t*)(this->file_buffer+sec_text_ptr->offset+mem_addr-sec_text_ptr->addr);
                                    }
                                }
                            }
                            
                            if(imm_val >= 0){
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
                                    map<uint32_t, pair<REF_TYPE, string>>::iterator iterator = this->derived_refs.find(reg_contains_imm);
                                    
                                    if(iterator != this->derived_refs.end()){
                                        //cout << iterator->second.second << endl;
                                        
                                        if (iterator->second.second.length() > 0) {
                                            iter_method->base_ref.push_back(iterator->second);
                                            
                                            if (iterator->second.first == IVAR_REF) {
                                                string ivar(iterator->second.second);
                                                string::size_type pos = ivar.find("@\"");
                                                string::size_type pos_end = ivar.rfind("\"");
                                                if(pos != string::npos && pos_end != string::npos && pos_end > (pos+2)){
                                                    string ivar_type = ivar.substr(pos+2, pos_end-(pos+2));
                                                    iter_method->base_ref.push_back(make_pair(INTERNAL_IVAR_TYPE, ivar_type));
                                                }
                                            }
                                        }
                                    }else if(reg_contains_imm >= cstring_addr_start && reg_contains_imm < cstring_addr_end){
                                        char* item = (char*)buffer_cstring_ptr+(reg_contains_imm-cstring_addr_start);
                                        iter_method->base_ref.push_back(make_pair(CFSTRING_REF, string(item)));
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
                                map<uint32_t, pair<REF_TYPE, string>>::const_iterator iterator = this->derived_refs.find(op->imm);
                                if(iterator != this->derived_refs.end()){
                                    //cout << iterator->second.second << endl;
                                    if(iterator->second.second.length() > 0) {
                                        iter_method->base_ref.push_back(iterator->second);
                                        
                                        if (iterator->second.first == IVAR_REF) {
                                            string ivar(iterator->second.second);
                                            string::size_type pos = ivar.find("@\"");
                                            string::size_type pos_end = ivar.rfind("\"");
                                            if(pos != string::npos && pos_end != string::npos && pos_end > (pos+2)){
                                                string ivar_type = ivar.substr(pos+2, pos_end-(pos+2));
                                                iter_method->base_ref.push_back(make_pair(INTERNAL_IVAR_TYPE, ivar_type));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if(!ignore_jump_out && jmp_out_instr.count(insn[idx].mnemonic) > 0){
                            //b, bx, b.w jump without link, indicates boundary of this function
                            break;
                        }
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
    }
    
    return 0;
}

/*
 guess invocation by ensembling class and selector
 */
void mach_desc::guess_invoke() {
    map<string, set<method_block*>> sel_blks;
    
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        for (vector<method_block>::iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            map<string, set<method_block*>>::iterator iter_sel_blks = sel_blks.find(iter_method->method_name);
            if (iter_sel_blks != sel_blks.end()) {
                iter_sel_blks->second.insert(&(*iter_method));
            } else {
                set<method_block*> blks;
                blks.insert(&(*iter_method));
                sel_blks.insert(make_pair(iter_method->method_name, blks));
            }
        }
    }
    
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        for (vector<method_block>::iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            for (vector<pair<REF_TYPE, string>>::const_iterator iter_refs = iter_method->base_ref.begin(); iter_refs != iter_method->base_ref.end(); ++iter_refs) {
                if (iter_refs->first != SEL_REF) {
                    continue;
                }
                
                map<string, set<method_block*>>::const_iterator iter_sel_blks = sel_blks.find(iter_refs->second);
                if (iter_sel_blks == sel_blks.end()) {
                    continue;
                }
                
                for (set<method_block*>::const_iterator iter_candidate = iter_sel_blks->second.begin(); iter_candidate != iter_sel_blks->second.end(); ++iter_candidate) {
                    if (*iter_candidate == &(*iter_method)) {
                        continue;
                    }
                    
                    vector<pair<REF_TYPE, string>>::iterator it = find(iter_method->base_ref.begin(), iter_method->base_ref.end(), make_pair(CLASS_REF, (*iter_candidate)->class_name));
                    if (it != iter_method->base_ref.end()) {
                        iter_method->guess_invokes.push_back(*iter_candidate);
                        break;
                    }
                }
            }
        }
    }
}

void mach_desc::export_to_json() {
    Json::Value root;
    
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        for (vector<method_block>::iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            Json::Value js_method;
            js_method["class"] = iter_class_blk->second.class_name;
            js_method["method"] = iter_method->method_name;
            
            Json::Value ref_array;
            for(vector<pair<REF_TYPE, string>>::const_iterator iter_refs = iter_method->base_ref.begin(); iter_refs != iter_method->base_ref.end(); ++iter_refs){
                Json::Value ref_item;
                ref_item["type"] = iter_refs->first;
                ref_item["value"] = iter_refs->second;
                ref_array.append(ref_item);
            }
            js_method["refs"] = ref_array;
            
            root.append(js_method);
        }
    }
    
    string path("");
    string suffix(".json");
    if (mach_desc::output_path.length() <= 0) {
        path = string(this->file_path+suffix);
    } else {
        path = this->output_path + "/" + this->file_sha256 + suffix;
    }
    
    std::ofstream fos(path, std::ofstream::out);
    Json::StyledWriter styledWriter;
    fos << styledWriter.write(root);
    fos.close();
}

void mach_desc::dump_raw_strings() {
    Json::Value root;
    
    set<string> abcdefg_set;
    
    for (map<uint32_t, pair<REF_TYPE, string>>::const_iterator iter = this->derived_refs.begin(); iter != this->derived_refs.end(); ++iter) {
        abcdefg_set.insert(iter->second.second);
    }
    
    for (set<string>::const_iterator iter_set = abcdefg_set.begin(); iter_set != abcdefg_set.end(); ++iter_set) {
        Json::Value js_item;
        js_item["r"] = *iter_set;
        root.append(js_item);
    }
    
    string path("");
    string suffix("_str");
    if (mach_desc::output_path.length() <= 0) {
        path = string(this->file_path+suffix);
    } else {
        path = this->output_path + "/" + this->file_sha256 + suffix;
    }
    
    std::ofstream fos(path, std::ofstream::out);
    Json::StyledWriter styledWriter;
    fos << styledWriter.write(root);
    fos.close();
}

int mach_desc::vc_analysis() {
    Json::Value root;
    set<string> view_controller_classes = {"_OBJC_CLASS_$_UITableViewController", "_OBJC_CLASS_$_UICollectionViewController", "_OBJC_CLASS_$_UIViewController",
        "_OBJC_CLASS_$_UITabBarController", "_OBJC_CLASS_$_UINavigationController",
        "_OBJC_CLASS_$_UIPageViewController"
    };
    
    bool added = false;
    do {
        added = false;
        for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
            if (view_controller_classes.count(iter_class_blk->second.super_class_name) > 0) {
                if(view_controller_classes.count(iter_class_blk->second.class_name) <= 0) {
                    view_controller_classes.insert(iter_class_blk->second.class_name);
                    added = true;
                }
            }
        }
    } while(added);
    
    view_controller_classes.erase("_OBJC_CLASS_$_UITableViewController");
    view_controller_classes.erase("_OBJC_CLASS_$_UICollectionViewController");
    view_controller_classes.erase("_OBJC_CLASS_$_UIViewController");
    view_controller_classes.erase("_OBJC_CLASS_$_UITabBarController");
    view_controller_classes.erase("_OBJC_CLASS_$_UINavigationController");
    view_controller_classes.erase("_OBJC_CLASS_$_UISplitViewController");
    view_controller_classes.erase("_OBJC_CLASS_$_UIPageViewController");
    
    set<string> considered_vc;
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        if(iter_class_blk->second.class_name.find("AppDelegate") == string::npos && view_controller_classes.count(iter_class_blk->second.class_name) <= 0) {
            continue;
        }
        //ignore viewcontrollers that appear in third party libraries
        size_t class_fingerprint = get_class_finger(iter_class_blk->second);
        map<size_t, int>::const_iterator library_iter = LibraryClasses.find(class_fingerprint);
        if(iter_class_blk->second.class_name.find("AppDelegate") == string::npos && library_iter != LibraryClasses.end() && library_iter->second > LIBRARY_THRESHOLD) {
            cout << "Library Found:" << iter_class_blk->second.class_name << ":" << library_iter->second << endl;
            continue;
        }
        considered_vc.insert(iter_class_blk->second.class_name);
    }
    
    set<string> root_views;
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        for (vector<method_block>::const_iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            bool set_root_view_api = false;
            
            for(vector<pair<REF_TYPE, string>>::const_iterator iter_refs = iter_method->base_ref.begin(); iter_refs != iter_method->base_ref.end(); ++iter_refs){
                if (iter_refs->second.find("setRootViewController") != string::npos) {
                    set_root_view_api = true;
                }
            }
            
            if (set_root_view_api == true) {
                for(vector<pair<REF_TYPE, string>>::const_iterator iter_refs = iter_method->base_ref.begin(); iter_refs != iter_method->base_ref.end(); ++iter_refs){
                    if (iter_class_blk->second.class_name.compare(iter_refs->second) && considered_vc.count(iter_refs->second) > 0) {
                        root_views.insert(iter_refs->second);
                    }
                }
            }
        }
    }
    
    map<string, string> vc_name_signature;
    
    Json::Value node_set;
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        if (considered_vc.count(iter_class_blk->second.class_name) <= 0) {
            continue;
        }
        
        struct vc_struct vc_item;
        vc_item.vc_name = iter_class_blk->second.class_name;
        vc_item.signature = get_class_finger(iter_class_blk->second);
        vc_item.call_openurl = false;
        vc_item.set_as_root_view = false;
        
        if (root_views.count(vc_item.vc_name) > 0) {
            vc_item.set_as_root_view = true;
        }
        
        for (vector<pair<string, string>>::const_iterator iter_ivar = iter_class_blk->second.instance_variables.begin(); iter_ivar != iter_class_blk->second.instance_variables.end(); ++iter_ivar){
            if (iOSConstants.count(iter_ivar->first) <= 0) {
                string str(iter_ivar->first);
                str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
                vc_item.bag_of_words.push_back(str);
            }
        }
        for (vector<method_block>::const_iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            if (iOSConstants.count(iter_method->method_name) <= 0) {
                string str(iter_method->method_name);
                str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
                vc_item.bag_of_words.push_back(str);
            }
            
            for(vector<pair<REF_TYPE, string>>::const_iterator iter_refs = iter_method->base_ref.begin(); iter_refs != iter_method->base_ref.end(); ++iter_refs){
                if (/*iter_refs->first == CFSTRING_REF && */iOSConstants.count(iter_refs->second) <= 0) {
                    string str(iter_refs->second);
                    str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
                    vc_item.bag_of_words.push_back(str);
                }
                
                if (is_http(iter_refs->second)) {
                    vc_item.urls.insert(iter_refs->second);
                }
                
                if (iter_refs->second.find("openURL") != string::npos) {
                    vc_item.call_openurl = true;
                }
            }
            
            //second-level invocations
            for (vector<struct method_block*>::const_iterator iter_guess_invokes = iter_method->guess_invokes.begin(); iter_guess_invokes != iter_method->guess_invokes.end(); ++iter_guess_invokes) {
                for(vector<pair<REF_TYPE, string>>::const_iterator iter_guess_refs = (*iter_guess_invokes)->base_ref.begin(); iter_guess_refs != (*iter_guess_invokes)->base_ref.end(); ++iter_guess_refs){
                    if (iOSConstants.count(iter_guess_refs->second) <= 0) {
                        string str(iter_guess_refs->second);
                        str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
                        vc_item.bag_of_words.push_back(str);
                    }
                }
            }
        }
        
        Json::Value node_item;
        node_item["vc_name"] = vc_item.vc_name;
        std::stringstream ss;
        ss << vc_item.signature;
        node_item["signature"] = ss.str();
        vc_name_signature.insert(make_pair(vc_item.vc_name, ss.str()));
        node_item["call_openurl"] = vc_item.call_openurl?1:0;
        node_item["set_as_root_view"] = vc_item.set_as_root_view?1:0;
        
        Json::Value words;
        for (vector<string>::const_iterator iter_words = vc_item.bag_of_words.begin(); iter_words != vc_item.bag_of_words.end(); ++iter_words) {
            words.append(*iter_words);
        }
        node_item["words"] = words;
        
        Json::Value ivars;
        for (vector<pair<string, string>>::const_iterator iter_ivars = iter_class_blk->second.instance_variables.begin(); iter_ivars != iter_class_blk->second.instance_variables.end(); ++iter_ivars) {
            Json::Value ivar_item;
            ivar_item["n"] = iter_ivars->first;
            ivar_item["t"] = iter_ivars->second;
            ivars.append(ivar_item);
        }
        node_item["ivars"] = ivars;
        
        Json::Value methods;
        for (vector<method_block>::const_iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method){
            methods.append(iter_method->method_name);
        }
        node_item["methods"] = methods;
        
        Json::Value urls;
        for (set<string>::const_iterator iter_urls = vc_item.urls.begin(); iter_urls != vc_item.urls.end(); ++iter_urls) {
            urls.append(*iter_urls);
        }
        node_item["urls"] = urls;
        node_set.append(node_item);
    }
    root["nodes"] = node_set;
    
    Json::Value vc_order;
    for (vector<string>::const_iterator iter_class_def_order = this->class_def_order.begin(); iter_class_def_order != this->class_def_order.end(); ++iter_class_def_order) {
        if (considered_vc.count(*iter_class_def_order) > 0) {
            map<string, string>::const_iterator iter_vc_name_sigature = vc_name_signature.find(*iter_class_def_order);
            if (iter_vc_name_sigature != vc_name_signature.end()) {
                vc_order.append(iter_vc_name_sigature->second);
            }
        }
    }
    root["vc_order"] = vc_order;
    
    Json::Value edge_set;
    for (map<string, class_block>::iterator iter_class_blk = this->class_blks.begin(); iter_class_blk != this->class_blks.end(); ++iter_class_blk){
        if (considered_vc.count(iter_class_blk->second.class_name) <= 0) {
            continue;
        }
        
        map<string, size_t> edges;
        for (vector<method_block>::const_iterator iter_method = iter_class_blk->second.class_or_instance_methods.begin(); iter_method != iter_class_blk->second.class_or_instance_methods.end(); ++iter_method) {
            for(vector<pair<REF_TYPE, string>>::const_iterator iter_refs = iter_method->base_ref.begin(); iter_refs != iter_method->base_ref.end(); ++iter_refs){
                if (considered_vc.count(iter_refs->second) > 0 && iter_class_blk->second.class_name.compare(iter_refs->second)) {
                    if (edges.count(iter_refs->second) <= 0) {
                        edges.insert(make_pair(iter_refs->second, 1));
                    } else {
                        edges[iter_refs->second]++;
                    }
                }
            }
        }
        
        // add reference from ViewController to its ViewController
        /*
        if (considered_vc.count(iter_class_blk->second.super_class_name) > 0 && edges.count(iter_class_blk->second.super_class_name) <= 0) {
            edges.insert(make_pair(iter_class_blk->second.super_class_name, 1));
        }
        */
        
        for (map<string, size_t>::const_iterator iter_edges = edges.begin(); iter_edges != edges.end(); ++iter_edges) {
            Json::Value edge_item;
            edge_item["src"] = iter_class_blk->second.class_name;
            edge_item["dst"] = iter_edges->first;
            std::stringstream ss;
            ss << iter_edges->second;
            edge_item["weight"] = ss.str();
            edge_set.append(edge_item);
        }
    }
    root["edges"] = edge_set;
    
    string path("");
    string suffix(".txt");
    if (mach_desc::output_path.length() <= 0) {
        path = string(this->file_path+suffix);
    } else {
        path = this->output_path + "/" + this->file_sha256 + suffix;
    }
    
    std::ofstream fos(path, std::ofstream::out);
    Json::StyledWriter styledWriter;
    fos << styledWriter.write(root);
    fos.close();
    
    return 0;
}

//import constants like iOSConstants, library class list, etc.
void mach_desc::localSetup() {
    ifstream iOSConstantsIf("./resources/iOSConstants");
    
    for (string line; getline(iOSConstantsIf,line);) {
        iOSConstants.insert(line);
    }
    iOSConstantsIf.close();
    
    ifstream libraryWLIf("./resources/LibraryClasses");
    for (string line; getline(libraryWLIf, line);){
        istringstream iss(line);
        vector<string> result;
        
        while(iss.good())
        {
            string substr;
            getline(iss, substr, ',');
            result.push_back(substr);
        }
        
        size_t finger;
        sscanf(result[1].c_str(), "%zu", &finger);
        LibraryClasses.insert(make_pair(finger, atoi(result[0].c_str())));
    }
    
    libraryWLIf.close();
}
