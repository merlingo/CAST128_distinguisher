#include "../CAST-128/CAST-128/stdafx.h"
#include <iostream>
#include <map>

//1- random plainText
BYTE* random_plaintext(int);
BYTE* CAST_ciphertext(BYTE*,int);
int* pc_pair(int round, std::map<int, int>* T);

