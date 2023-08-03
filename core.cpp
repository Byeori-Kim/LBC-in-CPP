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

#define one_block_len = 14;

byte* enc_one(string input_str, byte* key, byte f_link, byte b_link)
{
	byte cipher_block[AES::BLOCKSIZE] = {0, };
		    
	ECB_Mode<AES>::Encryption e;
	e.SetKey(key, sizeof(key));
				    
	cipher_block[0] = f_link;
	cipher_block[15] = b_link;
	memcpy(cipher_block + 1, input_str.c_str(), one_block_size);
	e.ProcessData(cipher_block, cipher_block, AES::BLOCKSIZE);
    
	return cipher_block;
}

byte* dec_one(byte* cipher, byte* key, byte check)
{
	byte plain[AES::BLOCKSIZE] = {0x00, };

	ECB_Mode<AES>::Decryption d;
	d.SetKey(key, sizeof(key));
	d.ProcessData(plain, cipher, key);
	if(check != 0x00 && plain[0] != check)
	{
		cout << "Error" << endl;
	}

	return plain;
}

byte* metadata_gen(int len)
{
	byte* metadata;
	int meta_len = len/AES::BLOCKSIZE;
	int remain = len;
	if(len%16 != 0)
	{	
		meta_len++;
	}
	metadata = new byte[meta_len]; 

	int i = 0;
	while(remain > AES::BLOCKSIZE)
	{   
		metadata[i] = (byte)0x10;
		remain -= AES::BLOCKSIZE;
		i++;
	}   
	metadata[i] = (byte)remain; 

    return metadata;
}

vector<byte> metadata_enc(byte* metadata, byte* key)
{
	vector<byte> meta_cipher;
	
	srand(time(NULL));
	byte front_link = (byte)rand()%256;
	byte back_link = (byte)rand()%256;
	byte tmp_block[AES::BLOCKSIZE] = {0, };
	
	int left_len = sizeof(metadata);
	byte* index = metadata;

	while(left_len > one_block_len)
	{
		string subStr(reinterpret_cast<const char*>index, one_block_len); 
		tmp_block = enc_one(subStr, key, front_link, back_link);
		
		for (int i = 0; i < AES::BLOCKSIZE; i++)
		{	
			meta_cipher.push_back(tmp_block[i]);
		}

		front_lonk = back_link;
		back_link = (byte)rand()%256;	
		
		index += one_block_len;
		left_len -= one_block_len;
	}
	tmp_block[0] = front_link;
	tmp_block[0] = back_link;
	memcpy(tmp_block + 1, index, left_len);
	fill_n(tmp_block + 1 + left_len, one_block_len - left_len, 0x00);
	e.ProcessData(tmp_block, tmp_block, AES::BLOCKSIZE);
	for (int i = 0; i < AES::BLOCKSIZE; i++)
	{	
		meta_cipher.push_back(tmp_block[i]);
	}
	return meta_cipher;
}

vector<byte> metadata_dec(byte* meta_cipher, byte* key)
{
	vector<byte> metadata;
	byte tmp_block[AES::BLOCKSIZE] = {0, };
	int left_len = sizeof(meta_cipher);
	byte* index = meta_cipher;
	byte check = 0x00;

	while(left_len > 0)
	{
		tmp_block = dec_one(index, key, check);
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
	byte tmp_block[AES::BLOCKSIZE] = {0x00, };
	int left_len = plain.length();

	byte f_link = f_iv;
	byte b_link = (byte)rand()%256;
	
	while(left_len > one_block_size)
	{
		string subStr = plain.substr(plain.length() - left_len, one_block_len);
		tmp_block = enc_one(subStr, key, f_link, b_link);
		for (int i = 0; i < AES::BLOCKSIZE; i++)
		{	
			cipher.push_back(tmp_block[i]);
		}
		f_link = b_link;
		b_link = (byte)rand%256;
		left_len -= one_block_len;
	}

	string subStr = plain.substr(plain.length() - left_len);
	while(subStr.length() != one_block_size)
	{
		subStr += '\x00';
	}

	tmp_block = enc_one(subStr, key, f_link, b_iv);
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

	byte tmp_block[AES::BLOCKSIZE] = {0x00, };
	
	byte* index = meta_cipher.data();
	byte check = 0x00;
	metadata = metadata_dec((byte*)meta_cipher.data(), key);
	
	for (int i = 0; i < metadata.size(); i++)
	{
		tmp_block = dec_one(index, key, check);
		for (int j = 0; j < metadata[i]; j++)
		{
			plain.push_back(tmp_block[j + 1]);
		}
		
		check = tmp_block[15];
		index += AES::BLOCKSIZE;
	}

	return plain;
}

/*class DL-ECB
{
private:
	vector<byte> data;
	Vector<byte> metadata;





}*/



