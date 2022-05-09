#include<iostream>
#include<fstream>
#include<string>
#include<vector>
#include<thread>
#include<csignal>
#include<iterator>
#include<cstdlib>
#include<openssl/md5.h>
#include<mutex>
#include<atomic>
#include<condition_variable>
#include<cmath>

struct decode_passw_struct{
    std::string entered_passw;
    std::string decoded_passw;
};

enum string_trans_option{
    all_capital, 
    first_capital, 
    all_lowercase
};

std::mutex found_password_mutex;
std::condition_variable cv;
std::atomic_size_t cracked_password(0);
std::atomic_size_t all_passwords(0);
std::atomic_size_t passw_num(0);
std::atomic_bool stop_threads;

int load_dictionary(
    const std::string f_name, 
    std::vector<std::string> &dictionary
    );
int load_hash_list(
    const std::string f_name,
    std::vector<std::string> &hash_list
    );
void producer_one_word_lowercase(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw
    );
void producer_one_word_all_capital(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw
    );
void producer_one_word_first_capital(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw
    );
void producer_two_word_lowercase(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw
    );
void producer_two_word_all_capital(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw
    );
void producer_two_word_first_capital(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw
    );

void consumer_thread(
    std::vector<decode_passw_struct> &decoded_passw
    );

void init_producers(
    std::vector<std::thread> &threads,
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw
    );
void stop_producer(
    std::vector<std::thread> &threads
    );

void terminate_producer(
    std::vector<std::thread> &threads
    );
int main(){
    std::vector<decode_passw_struct> decoded_passw;
    std::vector<std::string> dictionary;
    std::vector<std::string> hash_list;
    std::vector<std::thread> threads;
    std::string f_dic_name = "slownik.txt", f_hash_name="hasla.txt";

    /*std::cout << "Podaj nazwe slownika: ";
    std::cin >> f_dic_name;
    std::cout << std::endl << "Podaj nazwe pliku z hashami: ";
    std::cin >> f_hash_name;*/
    std::cout << "start" << std::endl;
    load_dictionary(f_dic_name, dictionary);
    load_hash_list(f_hash_name, hash_list);
    
    stop_threads = false;
    init_producers(threads, dictionary, hash_list, decoded_passw);
    std::thread consumer(consumer_thread, std::ref(decoded_passw));

    std::string buffer;
    while(1){
        std::cin >> buffer;
        if(buffer == "q"){
            break;
        }
        /*else if(buffer == "hasla"){
            buffer.clear();
            stop_producer(threads);
            cv.notify_one();
            consumer.join();
            terminate_producer(threads);
            consumer.~thread();
            std::cout << "Podaj nazwe nowego slownika: " << std::endl;
            std::cin >> f_hash_name;
            load_dictionary(f_hash_name, hash_list);
            init_producers(threads, dictionary, hash_list, decoded_passw);
            std::thread consumer(consumer_thread, std::ref(decoded_passw));
        }*/
    }
    stop_producer(threads);
    cv.notify_one();
    consumer.join();
    std::cout << "Koniec dzialania pracy lamacza hasel" << std::endl;
    return 0;
}



std::string &transform_word(std::string &trans_word, string_trans_option const &trans_option){
    switch(trans_option){
        case all_capital:
            for (auto& c : trans_word) {
            c = std::toupper(c);
            }
            return trans_word;
            break;
        case first_capital:
            trans_word[0] = toupper(trans_word[0]);
            return trans_word;
            break;
        case all_lowercase:
            for (auto& c : trans_word) {
            c = std::tolower(c);
            }
            return trans_word;
            break;
    }
    return trans_word;
}

std::string md5_hash(std::string &str){
    unsigned char pass_temp[32];
    char to_string[32];
    MD5(reinterpret_cast<const unsigned char*>(str.c_str()),
    str.length(), pass_temp);
    for(int i = 0; i < 16; i++)
    {
      sprintf(&to_string[i*2], "%02x", (unsigned int)pass_temp[i]);
    }
    return std::string(to_string);
}

void compare_word_with_passw(std::string word,     
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){

    decode_passw_struct tmp;
    //std::string tmp_word = word;
    for(size_t i(0); i < hash_list.size(); i++){
        if(md5_hash(word).compare(hash_list[i])==0){
            std::unique_lock<std::mutex> lock {found_password_mutex};
                tmp.entered_passw = hash_list[i];
                tmp.decoded_passw = word;
                decoded_passw.push_back(tmp);
                ++cracked_password;
                hash_list.erase(hash_list.begin()+i);
            cv.notify_one();
            lock.unlock();
        }
    }
}


// manage dictianry and hash_list 
int load_dictionary(const std::string f_name, std::vector<std::string> &dictionary){
    std::ifstream file(f_name, std::ios_base::in);
    std::string buffer;
    dictionary.clear();

    if(file.fail()){
        std::cerr<< "Nie udalo sie wczytac slownika" << std::endl;
        return -1;
    }

    while(1){
        file >> buffer;
        if(file.eof()){
            break;
        }
        dictionary.push_back(transform_word(buffer, all_lowercase));
    }
    file.close();
    return 0;


}

bool is_md5_hash(std::string arg){
    if(arg.length() == 32 && arg.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos){
        return true;
    }
    return false;
}

int load_hash_list(const std::string f_name, std::vector<std::string> &hash_list){
    std::ifstream file(f_name, std::ios_base::in);
    std::string buffer;
    hash_list.clear();

    if(file.fail()){
        std::cerr<< "Nie udalo sie wczytac pliku z haslami" << std::endl;
        return -1;
    }
        
    while(1){
        file >> buffer;
        if(file.eof()){
            break;
        }
        if(is_md5_hash(buffer)){
            hash_list.push_back(buffer);
        }
    }
    all_passwords = hash_list.size();
    file.close();
    return 0;
}


// producers one_word
void producer_one_word_lowercase(  
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){

    //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end() && !stop_threads; it++){
    for(size_t k(0);k < dictionary.size() && !stop_threads; k++){
        compare_word_with_passw(dictionary[k], hash_list, decoded_passw);
    }

    size_t i(0),j(10);
    size_t first,second;
    std::string tmp;
    while(!stop_threads){
        //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end();it++){
        for(size_t k(0);k < dictionary.size() && !stop_threads; k++){
            for(first=i;i<j && !stop_threads;first++){
                tmp=std::to_string(first)+dictionary[k];
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=dictionary[k]+std::to_string(first);
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                for(second=i;second<j && !stop_threads;second++){
                    tmp=std::to_string(first)+dictionary[k]+std::to_string(second);
                    compare_word_with_passw(tmp,hash_list, decoded_passw);
                }
            }
        }
        i=j;
        j*=10;
    }
}

void producer_one_word_all_capital(    
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){

    std::string trans_word_tmp;
    //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end() && !stop_threads; it++){
    for(size_t k(0);k < dictionary.size() && !stop_threads; k++){
        trans_word_tmp=dictionary[k];
        transform_word(trans_word_tmp, all_capital);
        compare_word_with_passw(trans_word_tmp,hash_list, decoded_passw);
    }

    size_t i(0),j(10);
    size_t first,second;
    std::string tmp;
    while(!stop_threads){
        //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end();it++){
        for(size_t k(0);k < dictionary.size() && !stop_threads; k++){
            trans_word_tmp=dictionary[k];
            transform_word(trans_word_tmp, all_capital);
            for(first=i;i<j && !stop_threads;++first){
                tmp=std::to_string(first)+trans_word_tmp;
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=trans_word_tmp+std::to_string(first);
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                for(second=i;second<j && !stop_threads;++second){
                    tmp=std::to_string(first)+trans_word_tmp+std::to_string(second);
                    compare_word_with_passw(tmp,hash_list, decoded_passw);
                }
            }
        }
        i=j;
        j*=10;
    }
}

void producer_one_word_first_capital(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){

    std::string trans_word_tmp;
    //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end() && !stop_threads; it++){
    for(size_t k(0);k < dictionary.size() && !stop_threads; k++){
        trans_word_tmp=dictionary[k];
        transform_word(trans_word_tmp, first_capital);
        compare_word_with_passw(trans_word_tmp,hash_list, decoded_passw);
    }

    size_t i(0),j(10);
    size_t first,second;
    std::string tmp;
    while(!stop_threads){
        //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end();it++){
        for(size_t k(0);k < dictionary.size() && !stop_threads; k++){
            trans_word_tmp=dictionary[k];
            transform_word(trans_word_tmp, first_capital);
            for(first=i;i<j && !stop_threads;++first){
                tmp=std::to_string(first)+trans_word_tmp;
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=trans_word_tmp+std::to_string(first);
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                for(second=i;second<j && !stop_threads;++second){
                    tmp=std::to_string(first)+trans_word_tmp+std::to_string(second);
                    compare_word_with_passw(tmp,hash_list, decoded_passw);
                }
            }
        }
        i=j;
        j*=10;
    }
}

void producer_two_word_lowercase(  
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){
    std::string tmp;

    //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end() && !stop_threads; it++){
    for(size_t k(0);k < dictionary.size()-1 && !stop_threads; k++){
        compare_word_with_passw(dictionary[k]+dictionary[k+1], hash_list, decoded_passw);
    }

    size_t i(0),j(10);
    size_t first,second;
    while(!stop_threads){
        //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end();it++){
        for(size_t k(0);k < dictionary.size()-1 && !stop_threads; k++){
            for(first=i;i<j && !stop_threads;first++){
                tmp=std::to_string(first)+dictionary[k]+dictionary[k+1];
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=dictionary[k]+dictionary[k+1]+std::to_string(first);
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=dictionary[k]+std::to_string(first)+dictionary[k+1];
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                for(second=i;second<j && !stop_threads;second++){
                    tmp=std::to_string(first)+dictionary[k]+dictionary[k+1]+std::to_string(second);
                    compare_word_with_passw(tmp,hash_list, decoded_passw);
                }
            }
        }
        i=j;
        j*=10;
    }
}

void producer_two_word_first_capital(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){

    std::string trans_word_tmp1;
    std::string trans_word_tmp2;
    //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end() && !stop_threads; it++){
    for(size_t k(0);k < dictionary.size()-1 && !stop_threads; k++){
        trans_word_tmp1=dictionary[k];
        trans_word_tmp2=dictionary[k+1];
        transform_word(trans_word_tmp1, first_capital);
        transform_word(trans_word_tmp2, first_capital);
        compare_word_with_passw(trans_word_tmp1+trans_word_tmp2,hash_list, decoded_passw);
    }

    size_t i(0),j(10);
    size_t first,second;
    std::string tmp;
    while(!stop_threads){
        //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end();it++){
        for(size_t k(0);k < dictionary.size()-1 && !stop_threads; k++){
            trans_word_tmp1=dictionary[k];
            trans_word_tmp2=dictionary[k+1];
            transform_word(trans_word_tmp1, first_capital);
            transform_word(trans_word_tmp2, first_capital);
            for(first=i;i<j && !stop_threads;++first){
                tmp=std::to_string(first)+trans_word_tmp1+trans_word_tmp2;
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=trans_word_tmp1+trans_word_tmp2+std::to_string(first);
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=trans_word_tmp1+std::to_string(first)+trans_word_tmp2;
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                for(second=i;second<j && !stop_threads;++second){
                    tmp=std::to_string(first)+trans_word_tmp1+trans_word_tmp2+std::to_string(second);
                    compare_word_with_passw(tmp,hash_list, decoded_passw);
                }
            }
        }
        i=j;
        j*=10;
    }
}

void producer_two_word_all_capital(
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){

    std::string trans_word_tmp1;
    std::string trans_word_tmp2;
    //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end() && !stop_threads; it++){
    for(size_t k(0);k < dictionary.size()-1 && !stop_threads; k++){
        trans_word_tmp1=dictionary[k];
        trans_word_tmp2=dictionary[k+1];
        transform_word(trans_word_tmp1, all_capital);
        transform_word(trans_word_tmp2, all_capital);
        compare_word_with_passw(trans_word_tmp1+trans_word_tmp2,hash_list, decoded_passw);
    }

    size_t i(0),j(10);
    size_t first,second;
    std::string tmp;
    while(!stop_threads){
        //for(std::vector<std::string>::iterator it(dictionary.begin());it!=dictionary.end();it++){
        for(size_t k(0);k < dictionary.size()-1 && !stop_threads; k++){
            trans_word_tmp1=dictionary[k];
            trans_word_tmp2=dictionary[k+1];
            transform_word(trans_word_tmp1, all_capital);
            transform_word(trans_word_tmp2, all_capital);
            for(first=i;i<j && !stop_threads;++first){
                tmp=std::to_string(first)+trans_word_tmp1+trans_word_tmp2;
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=trans_word_tmp1+trans_word_tmp2+std::to_string(first);
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                tmp=trans_word_tmp1+std::to_string(first)+trans_word_tmp2;
                compare_word_with_passw(tmp,hash_list, decoded_passw);
                for(second=i;second<j && !stop_threads;++second){
                    tmp=std::to_string(first)+trans_word_tmp1+trans_word_tmp2+std::to_string(second);
                    compare_word_with_passw(tmp,hash_list, decoded_passw);
                }
            }
        }
        i=j;
        j*=10;
    }
}

void sighup_handler(int signal){
    std::cout << "Wszystkie hasla: " << all_passwords <<std::endl;
    std::cout << "Zlamane hasla: " << cracked_password << std::endl;
    std::cout << "Zostalo do zlamania: " << all_passwords-cracked_password << std::endl;
}

void consumer_thread(std::vector<decode_passw_struct> &decoded_passw){
    
    while(!stop_threads){
        std::signal(SIGHUP, sighup_handler);
        std::signal(SIGINT, sighup_handler);
        std::unique_lock<std::mutex> lock {found_password_mutex};
        while(passw_num==cracked_password && !stop_threads){
            cv.wait(lock);
        }
        std::cout << "Hash hasla " << decoded_passw[passw_num].entered_passw << std::endl;
        std::cout << "Haslo po zlamaniu: " << decoded_passw[passw_num].decoded_passw << std::endl;
        ++passw_num;
    }
    std::cout << "Wszystkie hasla: " << all_passwords <<std::endl;
    std::cout << "Zlamane hasla: " << cracked_password << std::endl;
    std::cout << "Zostalo do zlamania: " << all_passwords-cracked_password << std::endl;
}

void init_producers(
    std::vector<std::thread> &threads,
    std::vector<std::string> &dictionary,
    std::vector<std::string> &hash_list,
    std::vector<decode_passw_struct> &decoded_passw){

    threads.push_back((std::thread(producer_one_word_all_capital, std::ref(dictionary), std::ref(hash_list), std::ref(decoded_passw))));
    threads.push_back((std::thread(producer_one_word_first_capital, std::ref(dictionary), std::ref(hash_list), std::ref(decoded_passw))));
    threads.push_back((std::thread(producer_one_word_lowercase, std::ref(dictionary), std::ref(hash_list), std::ref(decoded_passw))));
    threads.push_back((std::thread(producer_two_word_all_capital, std::ref(dictionary), std::ref(hash_list), std::ref(decoded_passw))));
    threads.push_back((std::thread(producer_two_word_first_capital, std::ref(dictionary), std::ref(hash_list), std::ref(decoded_passw))));
    threads.push_back((std::thread(producer_two_word_lowercase, std::ref(dictionary), std::ref(hash_list), std::ref(decoded_passw))));
}

void stop_producer(std::vector<std::thread> &threads){
    stop_threads = true;
    for(size_t k(0); k<threads.size();k++){
        threads[k].join();
    }
}

void terminate_producer(std::vector<std::thread> &threads){
    //stop_threads = false;
    for(size_t k(0); k<threads.size();k++){
        threads[k].~thread();
    }
}