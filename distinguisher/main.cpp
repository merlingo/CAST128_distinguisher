
#include "pc_pair.h"
#include <math.h>
#include <map>


int main()
{
    srand(time(0));
    int n=std::pow(2.0, 16.0), round=3;
    long max = std::pow(2.0, 32.0);
    std::cout<<max<<std::endl;
        // empty map container
    std::map<int, int> T;
    //int* T = new int[max];
     std::cout<<"lets begin with n="<<n<<"and round="<<round<<std::endl;

    for(int i=0;i<n;i++){
        // get random plaintext and produce cipher pair of it
        pc_pair(round, &T);
        std::cout<<i<<std::endl;
    }
    double result =0;
    //iterate all values and keys in T
    for(std::map<int,int>::iterator it = T.begin(); it != T.end(); ++it) {
        //update result for each count value in map
        double val = it->second;
        val = val / std::pow(2.0, 32.0);
        val = val - 1/ std::pow(2.0, 16.0);
        result = result + std::pow(2.0, 16.0)* std::pow(val, 2);
    }
    std::cout<<"****** ******** *******\n       RESULT:  "<<result<<"\n****** ******** *******\n";
return 0;
}