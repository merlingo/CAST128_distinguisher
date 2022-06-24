
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <cstring>
#include <math.h>
#include <map>
#include "../CAST-128/CAST-128/stdafx.h"
#include "../CAST-128/CAST-128/CAST-128_main.h"

 void random_plaintext(int StringLength, BYTE* cStrHex){
    //char cStrHex[(StringLength+1)] = {0};
    // Seed random:

    // Fill the char buffer
    int i=0;
       for(; i < StringLength; i++){
        cStrHex[i] =(unsigned char) rand();
//        sprintf(cStrHex+i, "%x", rand() % 16);
    }

    // Print hex string:
    printf("randomtext: %x\n", cStrHex);
    //return cStrHex;
}

BYTE* CAST_ciphertext(BYTE* pt,int round, BYTE* ct){
    //run CAST128 and produce ciphertext with round 3
	printf("\n");
 	BYTE key[16] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A };
    doCipher(round,pt,key,ct);
	printf("\n");
}

 void pc_pair(int round, std::map<int, int>* T){

    //produce random plaintext and its ciphertext pair.  plain text xor cipher text 
    BYTE pt[8];
    random_plaintext(8,pt);
    BYTE ct[8];
    CAST_ciphertext(pt,round, ct);
    printf("PLAINTEXT: ");
    //logfile<<"PLAINTEXT: ";
	for (int i = 0; i < 8; ++i) {
		printf("%x ", pt[i]);
        //logfile<<pt[i];

	}
    //logfile<<"\n";
    printf("\n");
    printf("CIPHERTEXT: ");
	for (int i = 0; i < 8; ++i) {
		printf("%x ", ct[i]);
	}
    printf("\n");


    BYTE x[4] = {0};
    for(int i=4; i<8;i++)
        x[i-4] = pt[i] ^ ct[i];

    printf("XOR of pt and ct: ");
	for (int i = 0; i < 4; ++i) {
		printf("%x ", x[i]);
	}
    printf("\n");
//insert T
    unsigned int t;
    std::memcpy(&t, x, sizeof(unsigned int));
    std::cout<<"t:"<<t<<std::endl;
    //T[t]++;
    std::map<int,int>::iterator it = T->find(t);
    if (it != T->end())
        it->second += 1;
    else
        T->insert(std::pair<int, int>(t, 1));
}