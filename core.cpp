#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include<cstdlib> 
#include<ctime> 
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include "core.h"

using namespace std;
using namespace CryptoPP;


void enc_one(string input_str, byte* key, byte f_link, byte b_link, byte* des)
{
	byte cipher_block[AES::BLOCKSIZE];

	ECB_Mode<AES>::Encryption e;
	e.SetKey(key, AES::DEFAULT_KEYLENGTH);

	cipher_block[0] = f_link;
	cipher_block[15] = b_link;
	memcpy(cipher_block + 1, input_str.c_str(), one_block_len);
	e.ProcessData(cipher_block, cipher_block, AES::BLOCKSIZE);
	memcpy(des, cipher_block, AES::BLOCKSIZE);
	return;
}

void dec_one(byte* cipher, byte* key, byte check, byte* des)
{
	byte plain[AES::BLOCKSIZE];

	ECB_Mode<AES>::Decryption d;
	d.SetKey(key, AES::DEFAULT_KEYLENGTH);
	d.ProcessData(plain, cipher, AES::BLOCKSIZE);
	if(check != 0x00 && plain[0] != check)
	{
		cout << "Error" << endl;
		memset(plain, 0x00, AES::BLOCKSIZE);
	}
	memcpy(des, plain, AES::BLOCKSIZE);

	return;
}

vector<byte> metadata_gen(int len)
{
	vector<byte> metadata;
	int remain = len;

	while(remain > one_block_len)
	{   
		metadata.push_back((byte)one_block_len);
		remain -= one_block_len;
	}   
	metadata.push_back((byte)remain); 

	return metadata;
}

vector<byte> metadata_enc(vector<byte> metadata, byte* key)
{
	srand(time(NULL));
	byte front_link = (byte)rand()%256;
	byte back_link = (byte)rand()%256;

	string meta_str(reinterpret_cast<char*>(metadata.data()), metadata.size());

	vector<byte> meta_cipher = encryption(meta_str, key, front_link, back_link);

	return meta_cipher;
}

vector<byte> metadata_dec(vector<byte> meta_cipher, byte* key)
{
	ECB_Mode<AES>::Decryption d;
	vector<byte> metadata;
	d.SetKey(key, AES::DEFAULT_KEYLENGTH);
	if(meta_cipher.size() != 0)
	{
		byte dec_meta[meta_cipher.size()] = {0x00, };
		byte tmp_meta[meta_cipher.size()/AES::BLOCKSIZE*one_block_len] = {0x00, };
		d.ProcessData(dec_meta, (const byte*)meta_cipher.data(), meta_cipher.size());
		byte f_iv = 0x00;
		byte b_iv = 0x00;
		for(int i = 0; i < sizeof(dec_meta); i += AES::BLOCKSIZE)
		{
			b_iv = dec_meta[i];
			if(f_iv != b_iv && f_iv != 0x00)
			{
				cout << "Error in metadata!!" <<endl;
			}
			else
			{
				memcpy(tmp_meta + i/AES::BLOCKSIZE*one_block_len, dec_meta + i + 1, one_block_len);
			}
			f_iv = dec_meta[i + AES::BLOCKSIZE - 1];
		}
		metadata.insert(metadata.begin(), tmp_meta, tmp_meta + sizeof(tmp_meta));
		while(metadata.back() == 0x00)
		{
			metadata.pop_back();
		}
	}

	return metadata;
}

vector<byte> encryption(string plain, byte* key, byte f_iv, byte b_iv)
{
	srand(time(NULL));
	ECB_Mode<AES>::Encryption e;
	e.SetKey(key, AES::DEFAULT_KEYLENGTH);
	vector<byte> cipher;

	while(plain.length()%one_block_len != 0)
	{
		plain += '\x00';
	}

	int cipher_len = plain.length()/one_block_len*AES::BLOCKSIZE;

	plain = (1, static_cast<char>(f_iv)) + plain;
	plain += (1, static_cast<char>(b_iv));
	for(int i = AES::BLOCKSIZE; i < cipher_len; i += AES::BLOCKSIZE)
	{
		byte link = (byte)rand()%256;
		byte twolink[2] = {link, link};
		string linkStr(reinterpret_cast<char*>(twolink), sizeof(twolink));
		plain.insert(i - 1, linkStr);
	}

	byte cipherBlocks[cipher_len] = {0x00, };
	e.ProcessData(cipherBlocks, (const byte*)plain.c_str(), cipher_len);
	cipher.insert(cipher.begin(), cipherBlocks, cipherBlocks + cipher_len);

	return cipher;
}

string decryption(vector<byte> cipher, vector<byte> meta_cipher, byte* key)
{
	string plain;
	vector<byte> metadata;
	byte check = 0x00;
	metadata = metadata_dec(meta_cipher, key);

	ECB_Mode<AES>::Decryption d;
	d.SetKey(key, AES::DEFAULT_KEYLENGTH);

	if(cipher.size() != 0)
	{
		byte dec_data[cipher.size()] = {0x00, };
		d.ProcessData(dec_data, (const byte*)cipher.data(), cipher.size());
		for(int i = 0; i < metadata.size(); i ++)
		{
			if(check != dec_data[i*AES::BLOCKSIZE] && check != 0x00)
			{
				cout << "Error in data!!" <<endl;
			}
			else
			{
				for (int j = 0; j < (int)metadata[i]; j++)
				{
					plain.push_back(dec_data[i*AES::BLOCKSIZE + j + 1]);
				}

			}
			check = dec_data[(i + 1)*AES::BLOCKSIZE - 1];
		}
	}

	return plain;
}

int search_block_index(vector<byte> metadata, int index)
{
	int check = index;
	int block_index = 0;
	while(block_index < metadata.size())
	{
		check -= metadata[block_index];
		if (check < 0)
			return block_index;
		else if (check > 0)
			block_index++;
		else
			return block_index + 1;
	}
	return block_index;
}

Modi_info::Modi_info(int index, int len)
{
	modi_index = index;
	modi_len = len;
	del_index = 0;
	del_len = 0;
	ins_index = 0;

}
void Modi_info::update_meta(vector<byte> metadata)
{
	this->new_meta.clear();
	this->new_meta.insert(this->new_meta.end(), metadata.begin(), metadata.end());

	return;
}

void Modi_info::update_insertion(vector<byte> list)
{
	this->ins_list.clear();
	this->ins_list.insert(ins_list.end(), list.begin(), list.end());
	return;
}

void Modi_info::update_insertion(byte* list)
{
	this->ins_list.clear();
	this->ins_list.insert(ins_list.end(), list, list + AES::BLOCKSIZE);
	return;
}

void Modi_info::unpacking(vector<byte> data, vector<byte> metadata)
{
	data.erase(data.begin() + del_index, data.begin() + del_index + del_len);
	data.insert(data.begin() + ins_index, ins_list.begin(), ins_list.end());
	metadata.clear();
	metadata.insert(metadata.begin(), new_meta.begin(), new_meta.end());
	return;
}


DL_ECB::DL_ECB(byte* key)
{
	memcpy(this->key, key, AES::BLOCKSIZE);
}

DL_ECB::~DL_ECB() {}

vector<byte> DL_ECB::print_data()
{
	return this->data;
}

vector<byte> DL_ECB::print_meta()
{
	return this->metadata;
}

Modi_info DL_ECB::Insertion(string text, int index)
{
	srand(time(NULL));
	Modi_info modi(index, text.length());
	vector<byte> meta_plain = metadata_dec(this->metadata, this->key);
	string insert_text = text;
	int block_index = 0;
	byte f_link = 0x00;
	byte b_link = 0x00;

	if(index == 0 && meta_plain.size() == 0)
	{
		f_link = (byte)rand()%256;
		b_link = f_link;
	}

	else
	{
		block_index = search_block_index(meta_plain, index);
		int in_index = index;
		if (block_index == meta_plain.size())
		{
			block_index--;
			in_index = (int)meta_plain[block_index];
		}
		else
		{
			for (int i = 0; i < block_index; i++)
			{
				in_index -= (int)meta_plain[i];
			}
		}

		byte tmp_block[AES::BLOCKSIZE];
		dec_one(this->data.data() + AES::BLOCKSIZE*block_index, this->key, 0x00, tmp_block);
		f_link = tmp_block[0];
		b_link = tmp_block[15];

		string front = "";
		for(int i = 0; i < in_index; i++)
		{
			front += tmp_block[i + 1];
		}
		string back = "";
		for(int i = in_index; i < one_block_len; i++)
		{
			back += tmp_block[i + 1];
		}
		insert_text = front + insert_text + back;

		data.erase(data.begin() + AES::BLOCKSIZE*block_index, data.begin() + AES::BLOCKSIZE*(block_index + 1));
		meta_plain.erase(meta_plain.begin() + block_index);
		modi.del_index = AES::BLOCKSIZE*block_index;
		modi.del_len = AES::BLOCKSIZE;
	}

	vector<byte> new_meta = metadata_gen(insert_text.size());
	vector<byte> new_cipher = encryption(insert_text, this->key, f_link, b_link);
	this->data.insert(this->data.begin() + block_index*AES::BLOCKSIZE, new_cipher.begin(), new_cipher.end());

	modi.ins_index = block_index*AES::BLOCKSIZE;
	modi.update_insertion(new_cipher);

	meta_plain.insert(meta_plain.begin() + block_index, new_meta.begin(), new_meta.end());
	this->metadata = metadata_enc(meta_plain, key);

	modi.update_meta(this->metadata);
	return modi;
}

Modi_info DL_ECB::Deletion(int del_len, int index)
{
	srand(time(NULL));
	vector<byte> meta_plain = metadata_dec(this->metadata, this->key);
	byte f_link = 0x00;
	byte b_link = 0x00;

	Modi_info modi(index, -(del_len));
	int f_block_index = search_block_index(meta_plain, index);
	int b_block_index = search_block_index(meta_plain, index + del_len);
	int f_in_index = index;
	int b_in_index = index + del_len; 

	for (int i = 0; i < f_block_index; i++)
	{
		f_in_index -= meta_plain[i];
	}

	for (int i = 0; i < b_block_index; i++)
	{
		b_in_index -= meta_plain[i];
	}

	if (f_in_index == 0 && b_in_index == 0)
	{
		//cout << "case1" << endl;
		if (f_block_index == 0)
		{
			if (b_block_index == meta_plain.size())				// remove all
			{
				modi.del_index = 0;
				modi.del_len = this->data.size();
				this->data.clear();
				this->metadata.clear();
			}

			else
			{
				byte tmp_block[AES::BLOCKSIZE];
				dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
				f_link = tmp_block[0];
				dec_one(this->data.data() + b_block_index*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
				tmp_block[0] = f_link;
				this->data.erase(this->data.begin() + f_block_index*AES::BLOCKSIZE, this->data.begin() + b_block_index*AES::BLOCKSIZE);
				modi.del_index = f_block_index*AES::BLOCKSIZE;
				modi.del_len = (b_block_index - f_block_index)*AES::BLOCKSIZE;
				string tmp_str;
				for(int i = 1; i < one_block_len; i++)
				{
					tmp_str += tmp_block[i];
				}
				enc_one(tmp_str, this->key, tmp_block[0], tmp_block[15], tmp_block);
				this->data.insert(this->data.begin() + f_block_index * AES::BLOCKSIZE, tmp_block, tmp_block + AES::BLOCKSIZE);
				modi.ins_index = f_block_index*AES::BLOCKSIZE;
				modi.update_insertion(tmp_block);
			}
		}
		else
		{
			byte tmp_block[AES::BLOCKSIZE];
			dec_one(this->data.data() + (b_block_index - 1)*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
			b_link = tmp_block[15];
			dec_one(this->data.data() + (f_block_index - 1)*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
			this->data.erase(this->data.begin() + (f_block_index - 1)*AES::BLOCKSIZE, this->data.begin() + b_block_index*AES::BLOCKSIZE);
			modi.del_index = (f_block_index - 1)*AES::BLOCKSIZE;
			modi.del_len = (b_block_index - f_block_index + 1)*AES::BLOCKSIZE;
			string tmp_str;
			for (int i = 0; i < one_block_len; i++)
			{
				tmp_str += tmp_block[i+1];
			}
			enc_one(tmp_str, this->key, tmp_block[0], b_link, tmp_block);
			this->data.insert(this->data.begin() + (f_block_index - 1)*AES::BLOCKSIZE, tmp_block, tmp_block + AES::BLOCKSIZE);
			modi.ins_index = (f_block_index - 1)*AES::BLOCKSIZE;
			modi.update_insertion(tmp_block);
		}
		meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);
	}

	else if (f_in_index == 0 && b_in_index != 0)
	{
		//cout << "case2" << endl;
		byte tmp_block[AES::BLOCKSIZE];
		dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
		f_link = tmp_block[0];
		dec_one(this->data.data() + b_block_index*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
		b_link = tmp_block[15];
		string tmp_str;
		for (int i = b_in_index; i < one_block_len; i++)
		{
			tmp_str += tmp_block[i + 1];
		}
		enc_one(tmp_str, this->key, f_link, b_link, tmp_block);
		this->data.erase(this->data.begin() + f_block_index*AES::BLOCKSIZE,this->data.begin() +  (b_block_index + 1)*AES::BLOCKSIZE);
		modi.del_index = f_block_index*AES::BLOCKSIZE;
		modi.del_len = (b_block_index + 1 - f_block_index)*AES::BLOCKSIZE;
		this->data.insert(this->data.begin() + f_block_index*AES::BLOCKSIZE, tmp_block,tmp_block + AES::BLOCKSIZE);
		modi.ins_index = f_block_index*AES::BLOCKSIZE;
		modi.update_insertion(tmp_block);
		meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index + 1);
		meta_plain.insert(meta_plain.begin() + f_block_index, (byte)tmp_str.length());
	}

	else if (f_in_index != 0 && b_in_index == 0)
	{
		//cout << "case3" << endl;
		byte tmp_block[AES::BLOCKSIZE];
		dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
		f_link = tmp_block[0];
		string tmp_str;
		for (int i = 0; i < f_in_index; i++)
		{
			tmp_str += tmp_block[i + 1];
		}
		dec_one(this->data.data() + (b_block_index - 1)*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
		b_link = tmp_block[15];
		enc_one(tmp_str, this->key, f_link, b_link, tmp_block);
		this->data.erase(this->data.begin() + f_block_index*AES::BLOCKSIZE, this->data.begin() + b_block_index*AES::BLOCKSIZE);
		modi.del_index = f_block_index*AES::BLOCKSIZE;
		modi.del_len = (b_block_index - f_block_index)*AES::BLOCKSIZE;

		this->data.insert(this->data.begin() + f_block_index*AES::BLOCKSIZE, tmp_block, tmp_block + AES::BLOCKSIZE); 
		modi.ins_index = f_block_index&AES::BLOCKSIZE;
		modi.update_insertion(tmp_block);
		meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);
		meta_plain.insert(meta_plain.begin() + f_block_index, (byte)tmp_str.length());
	}

	else
	{
		//cout << "case4" << endl;
		byte tmp_block[AES::BLOCKSIZE];
		dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
		f_link = tmp_block[0];
		string tmp_str;
		for (int i = 0; i < f_in_index; i++)
		{
			tmp_str += tmp_block[i + 1];
		}
		dec_one(this->data.data() + b_block_index*AES::BLOCKSIZE, this->key, 0x00, tmp_block);
		b_link = tmp_block[15];
		for(int i = b_in_index; i < one_block_len; i++)
		{
			tmp_str += tmp_block[i + 1];
		}
		vector<byte> tmp_enc = encryption(tmp_str, this->key, f_link, b_link);
		this->data.erase(this->data.begin() + f_block_index*AES::BLOCKSIZE, this->data.begin() + (b_block_index + 1)*AES::BLOCKSIZE);
		modi.del_index = f_block_index*AES::BLOCKSIZE;
		modi.del_len = (b_block_index + 1 - f_block_index)*AES::BLOCKSIZE;
		this->data.insert(this->data.begin() + f_block_index*AES::BLOCKSIZE, tmp_enc.begin(), tmp_enc.end());
		modi.ins_index = f_block_index*AES::BLOCKSIZE;
		modi.update_insertion(tmp_enc);
		meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index + 1);
		if(tmp_str.length() > one_block_len)
		{
			meta_plain.insert(meta_plain.begin() + f_block_index, (byte)(tmp_str.length()%one_block_len));
			meta_plain.insert(meta_plain.begin() + f_block_index, (byte)one_block_len);
		}
		else
		{
			meta_plain.insert(meta_plain.begin() + f_block_index, (byte)tmp_str.length());
		}
	}

	this->metadata = metadata_enc(meta_plain, key);
	modi.update_meta(this->metadata);

	return modi;
}






