typedef map<string, vector<pair<ref_type, string>>>::iterator map_str_2_vec_pair_iter;
typedef vector<pair<ref_type, string>>::iterator vec_pair_type_string_iter;
typedef map<string, vector<pair<ref_type, string>>>::const_iterator map_str_2_vec_iter_const;
typedef vector<pair<ref_type, string>>::const_iterator vec_pair_type_string_iter_const;

class mach_desc{
public:
    mach_desc(string path): file_path(path), file_sha256(path), file_buffer(NULL), idx_data_seg(0), idx_dyld_info_cmd(0), idx_dysymtab_cmd(0), idx_linkedit_seg(0), idx_symtab_cmd(0), idx_text_seg(0){
        if(path.length() <= 0){
            return;
        }
        
        if(!mach_desc::is_mach_o_file(path)){
            return;
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
        this->get_reference_details();
        this->post_process_invocations();
        this->get_ui_events();
        this->export_references();
    }
    ~mach_desc(){
        if(this->file_buffer != NULL){
            delete [] this->file_buffer;
            this->file_buffer = NULL;
            this->file_len = -1;
        }
    }
    
    void release_file_buffer(){
        if(this->file_buffer != NULL){
            delete [] this->file_buffer;
            this->file_buffer = NULL;
            this->file_len = -1;
        }
    }
    
    string get_file_path() const{
        return this->file_path;
    }

    map<string, method_desc> get_methods_name2desc(){
        return this->methods_name2desc;
    }

    map<string, set<string>> get_class_2_strings(bool only_cfstring=true, size_t min_len=5) const;
    set<string> extend_class_set_by_const(const set<string>& anchor_class_set, const vector<pair<string, set<string>>>& android_cls_2_strings) const;
    set<pair<uint32_t, vector<string>>> get_all_call_chains(set<string> classes_set, set<string> ios_strings);
    set<string> get_string_related_with_classes(const set<string>& classe, bool only_cfstring=true, size_t min_len=5);
    
    static bool is_mach_o_file(const string& file_path);
    
private:
    string file_path;
    string file_sha256;
    
    size_t idx_mach_header;
    size_t idx_text_seg;
    size_t idx_data_seg;
    size_t idx_linkedit_seg;
    size_t idx_symtab_cmd;
    size_t idx_dysymtab_cmd;
    size_t idx_dyld_info_cmd;
    
    int extract_mach_sects();
    map<string, size_t> sections; //sections in __TEXT and __DATA segment and their indexes
    
    void read_file_to_memory();
    
    size_t file_len;
    
    int extract_methods_and_refs();
    //methods defined in this file, recover from database
    map<uint32_t, method_desc> methods_addr2desc;
    map<string, method_desc> methods_name2desc;    
    //const used by methods, recover from database
    map<string, vector<pair<ref_type, string>>> const_in_methods;
    
    //they are only used during Mach-O initialization, does not store or recover from database
    map<string, set<string>> delegates_implementations;
    map<string, string> class_superclass;
    map<string, set<string>> class_prots;
    map<uint32_t, pair<ref_type, string>> references_map;

    //log methods that accesses the same ivar
    map<string, set<string>> ivar_usage_map;
    
    int get_reference_details();
    void post_process_invocations();
    
    mach_desc(){}
    void export_references();
    void get_ui_events();
    
    int fat_file_to_thin(const string& file_path);
};