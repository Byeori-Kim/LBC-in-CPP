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


byte* enc_one(string input_str, byte* key, byte f_link, byte b_link)
{
	byte* cipher_block = new byte[AES::BLOCKSIZE];

	ECB_Mode<AES>::Encryption e;
	e.SetKey(key, AES::DEFAULT_KEYLENGTH);

	cipher_block[0] = f_link;
	cipher_block[15] = b_link;
	memcpy(cipher_block + 1, input_str.c_str(), one_block_len);
	e.ProcessData(cipher_block, cipher_block, AES::BLOCKSIZE);

	return cipher_block;
}

byte* dec_one(byte* cipher, byte* key, byte check)
{
	byte* plain = new byte[AES::BLOCKSIZE];

	ECB_Mode<AES>::Decryption d;
	d.SetKey(key, AES::DEFAULT_KEYLENGTH);
	d.ProcessData(plain, cipher, AES::BLOCKSIZE);
	if(check != 0x00 && plain[0] != check)
	{
		cout << "Error" << endl;
	}

	return plain;
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
	vector<byte> meta_cipher;

	srand(time(NULL));
	byte front_link = (byte)rand()%256;
	byte back_link = (byte)rand()%256;

	int left_len = metadata.size();
	byte* index = metadata.data();

	while(left_len > one_block_len)
	{
		string subStr((const char*)index, one_block_len); 
		byte* tmp_block = enc_one(subStr, key, front_link, back_link);

		for (int i = 0; i < AES::BLOCKSIZE; i++)
		{	
			meta_cipher.push_back(tmp_block[i]);
		}

		front_link = back_link;
		back_link = (byte)rand()%256;	

		index += one_block_len;
		left_len -= one_block_len;
	}
	string subStr((const char*)index, left_len);
	for (int i = 0; i < one_block_len - left_len; i++)
	{
		subStr += '\x00';
	}
	byte* tmp_block = enc_one(subStr, key, front_link, back_link);
	for (int i = 0; i < AES::BLOCKSIZE; i++)
	{	
		meta_cipher.push_back(tmp_block[i]);
	}
	return meta_cipher;
}

vector<byte> metadata_dec(vector<byte> meta_cipher, byte* key)
{
	vector<byte> metadata;
	int left_len = meta_cipher.size();
	byte* index = meta_cipher.data();
	byte check = 0x00;
	if (left_len == 0)
		return metadata;
	while(left_len > 0)
	{
		byte* tmp_block = dec_one(index, key, check);
		for (int i = 1; i < AES::BLOCKSIZE - 1; i++)
		{	
			metadata.push_back(tmp_block[i]);
		}

		check = tmp_block[15];
		index += AES::BLOCKSIZE;
		left_len -= AES::BLOCKSIZE;
	}
	while(metadata.back() == 0x00)
	{
		metadata.pop_back();
	}

	return metadata;
}

vector<byte> encryption(string plain, byte* key, byte f_iv, byte b_iv)
{
	srand(time(NULL));

	vector<byte> cipher;
	int left_len = plain.length();

	byte f_link = f_iv;
	byte b_link = (byte)rand()%256;

	while(left_len > one_block_len)
	{
		string subStr = plain.substr(plain.length() - left_len, one_block_len);
		byte* tmp_block = enc_one(subStr, key, f_link, b_link);
		for (int i = 0; i < AES::BLOCKSIZE; i++)
		{	
			cipher.push_back(tmp_block[i]);
		}
		f_link = b_link;
		b_link = (byte)rand()%256;
		left_len -= one_block_len;
	}

	string subStr = plain.substr(plain.length() - left_len);
	while(subStr.length() != one_block_len)
	{
		subStr += '\x00';
	}

	byte* tmp_block = enc_one(subStr, key, f_link, b_iv);
	for (int i = 0; i < AES::BLOCKSIZE; i++)
	{	
		cipher.push_back(tmp_block[i]);
	}

	return cipher;
}

string decryption(vector<byte> cipher, vector<byte> meta_cipher, byte* key)
{
	string plain;
	vector<byte> metadata;

	byte* index = cipher.data();
	byte check = 0x00;
	metadata = metadata_dec(meta_cipher, key);

	for (int i = 0; i < metadata.size(); i++)
	{
		byte* tmp_block = dec_one(index, key, check);
		for (int j = 0; j < (int)metadata[i]; j++)
		{
			plain.push_back(tmp_block[j + 1]);
		}

		check = tmp_block[15];
		index += AES::BLOCKSIZE;
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

void Modi_info::update_deletion(int index, int len)
{
	this->del_index = index;
	this->del_len = len;

	return;
}

void Modi_info::update_insertion(int index, vector<byte> list)
{
	this->ins_index = index;
	this->ins_list.clear();
	this->ins_list.insert(ins_list.end(), list.begin(), list.end());
}

void Modi_info::unpacking(vector<byte> data, vector<byte> metadata)
{
	metadata.clear();
	metadata.insert(metadata.end(), this->new_meta.begin(), this->new_meta.end());

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

		byte* tmp_block = dec_one(this->data.data() + AES::BLOCKSIZE*block_index, this->key, 0x00);
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
	}

	vector<byte> new_cipher = encryption(insert_text, this->key, f_link, b_link);
	vector<byte> new_meta = metadata_gen(insert_text.size());
	this->data.insert(this->data.begin() + block_index*AES::BLOCKSIZE, new_cipher.begin(), new_cipher.end());
	meta_plain.insert(meta_plain.begin() + block_index, new_meta.begin(), new_meta.end());
	this->metadata = metadata_enc(meta_plain, key);

	return modi;
}
/*
Modi_info DL_ECB::Deletion(int del_len, int index)
{
	srand(time(NULL));
	vector<byte> meta_plain = metadata_dec(this->metadata, this->key);
	byte f_link = 0x00;
	byte b_link = 0x00;
	
	Modi_info modi_info;
	int f_block_index = search_block_index(meta_plain, index);
	int b_block_index = search_block_index(meta_plain, index + del_len - 1);
	int f_in_index = index;
	int b_in_index = index + del_len - 1; 

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
		if (f_block_index == 0)
		{
			if (b_block_index == meta_plain.size())				// remove all
			{
				this->data.clean();
				this->metadata.clean();
			}

			else
			{
				byte tmp_block[AES::BLOCKSIZE] = dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00);
				f_link = tmp_block[0];
				tmp_block = dec_one(data + b_block_index*AES::BLOCKSIZE, this->key, 0x00);
				tmp_block[0] = f_link;
				this->data.erase(this->data.begin() + f_block_index*AES::BLOCKSIZE, this->data.begin() + (b_block_index + 1)*AES::BLOCKSIZE - 1);
				string tmp_str;
				for(int i = 0; i < AES::BLOCKSIZE - 2; i++)
				{
					tmp_str.append(tmp_block[i + 1];
							}
							tmp_block = enc_one(tmp_str, this->key, tmp_block[0], tmp_block[15]);
							this->data.insert(this->data.begin() + f_block_index * AES::BLOCKSIZE, tmp_block);
							}
							}
							else
							{
							byte tmp_block[AES::BLOCKSIZE] = dec_one(this->data.data() + (b_block_index - 1)*AES::BLOCKSIZE, 0x00);
							b_link = tmp_block[15];
							tmp_block = dec_one(this->data.data() + (f_block_index - 1)*AES::BLOCKSIZE, this->key, 0x00);
							this->data.erase(this->data.begin() + (f_block_index - 1)*AES::BLOCKSIZE, this->data.begin() + b_block_index*AES::BLOCKSIZE - 1);
							string tmp_str;
							for (int i = 0; i < AES::BLOCKSIZE - 2; i++)
							{
							tmp_str.append(tmp_block[i+1]);
							}
							tmp_block = enc_one(tmp_str, this->key, tmp_block[0], b_link);
							this->data.insert(this->data.begin() + f_block_index*AES::BLOCKSIZE, tmp_block);

							}
					meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);
	}

	else if (f_in_index == 0 && b_in_index != 0)
	{
		byte tmp_block[AES::BLOCKSIZE] = dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00);
		f_link = tmp_block[0];
		tmp_block = dec_one(this->data.data() + b_block_index*AES::BLOCKSIZE, this->key, 0x00);
		b_link = tmp_block[15];
		string tmp_str;
		for (int i = b_in_index; i < AES::BLOCKSIZE - 2; i++)
		{
			tmp_str.append(tmp_block[i + 1]);
		}
		tmp_block = enc_one(tmp_str, this->key, f_link, b_link);
		this->data.erase(this->data.begin() + (f_block_index - 1)*AES::BLOCKSIZE,this->data.begin() +  b_block_index*AES::BLOCKSIZE);
		this->data.insert(this->data.begin() + (f_block_index - 1)*AES::BLOCKSIZE, tmp_block, AES::BLOCKSIZE);

		meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);
		meta_plain.insert(meta_plain.begin() + f_block_index, (byte)tmp_str.length());
	}

	else if (f_in_index != 0 && b_in_index == 0)
	{
		byte tmp_block[AES::BLOCKSIZE] = dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00);
		f_link = tmp_block[0];
		string tmp_str;
		for (int i = 0; i < f_in_index; i++)
		{
			tmp_str.append(tmp_block[i + 1]);
		}
		tmp_block = dec_one(this->data.data() + (b_block_index - 1)*AES::BLOCKSIZE, this->key, 0x00);
		b_link = tmp_block[15];
		tmp_block = enc_one(tmp_str, this->key, f_link, b_link);
		this->data.erase(this->data.begin() + f_block_index*AES::BLOCKSIZE, this->data.begin() + b_block_index*AES::BLOCKSIZE);
		this->data.insert(this->data.begin() + f_block_index*AES::BLOCKSIZE, tmp_block, AES::BLOCKSIZE); 

		meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);
		meta_plain.insert(meta_plain.begin() + f_block_index, (byte)tmp_str.length());
	}

	else
	{
		byte tmp_block[AES::BLOCKSIZE] = dec_one(this->data.data() + f_block_index*AES::BLOCKSIZE, this->key, 0x00);
		f_link = tmp_block[0];
		string tmp_str;
		for (int i = 0; i < f_in_index; i++)
		{
			tmp_str.append(tmp_block[i + 1]);
		}
		tmp_block = dec_one(this->data.data() + b_block_index*AES::BLOCKSIZE, rhis->key, 0x00);
		b_link = tmp_block[15];
		for(int i = b_in_index; i < AES::BLOCKSIZE - 2; i++)
		{
			tmp_str.append(tmp_block[i + 1]);
		}
		vector<byte> tmp_enc = encryption(tmp_str, this->key, f_link, b_link);
		this->data.erase(this->data.begin() + f_block_index*AES::BLOCKSIZE, this->data.begin() + b_block_index*AES::BLOCKSIZE);
		this->data.insert(this->data.data() + f_block_index*AES::BLOCKSIZE, tmp_enc.data(), tmp_enc.size());

		meta_plain.erase(meta_plain.begin() + f_block_index, meta_plain.begin() + b_block_index);
		if(tmp_str.length() > AES::BLOCKSIZE)
		{
			meta_plain.insert(meta_plain.begin() + f_block_index, (byte)(tmp_str.length()%AES::BLOCKSIZE));
			meta_plain.insert(meta_plain.begin() + f_block_index, 0x10);
		}
		else
		{
			meta_plain.insert(meta_plain.begin() + f_block_index, (byte)tmp_str.length());
		}
	}


	return modi_info;
}*/






