#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include<cstdlib>
#include<ctime>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;

#define one_block_len 14

class Modi_info
{

private:
	int modi_index; 
	int modi_len;
	int del_index;
	int del_len;
	int ins_index;
	vector<byte> new_meta;
	vector<byte> ins_list;

public:
	Modi_info(int index, int len);
	void update_meta(vector<byte> metadata);
	void update_deletion(int index, int len);
	void update_insertion(int index, vector<byte> list);
	void unpacking(vector<byte> data, vector<byte> metadata);
};

class DL_ECB
{

private:
	vector<byte> data;
	vector<byte> metadata;
	byte key[AES::BLOCKSIZE];

public:
	DL_ECB(byte* key);

	~DL_ECB();

	vector<byte> print_data();

	vector<byte> print_meta();

	Modi_info Insertion(string text, int index);

	Modi_info Deletion(int del_len, int index);
};

byte* enc_one(string input_str, byte* key, byte f_link, byte b_link);

byte* dec_one(byte* cipher, byte* key, byte check);

vector<byte> metadata_gen(int len);

vector<byte> metadata_enc(vector<byte> metadata, byte* key);

vector<byte> metadata_dec(vector<byte> meta_cipher, byte* key);

vector<byte> encryption(string plain, byte* key, byte f_iv, byte b_iv);

string decryption(vector<byte> cipher, vector<byte> meta_cipher, byte* key);

int search_block_index(vector<byte> metadata, int index);


