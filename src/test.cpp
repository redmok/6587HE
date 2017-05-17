#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <algorithm>

using namespace std;
/**
 *
 */
int main(int argc, char** argv) {

     /* On our trusted system we generate a new key
     * (or read one in) and encrypt the secret data set.
     */

    long m=0, p=2, r=1; // Native plaintext space
                        // Computations will be 'modulo p'
    long L=16;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long security = 128;
    ZZX G;
    m = FindM(security,L,c,p, d, 0, 0);

    FHEcontext context(m, p, r);
    // initialize context
    buildModChain(context, L, c);
    // modify the context, adding primes to the modulus chain
    FHESecKey secretKey(context);
    // construct a secret key structure
    const FHEPubKey& publicKey = secretKey;
    // an "upcast": FHESecKey is a subclass of FHEPubKey

    //if(0 == d)
    G = context.alMod.getFactorsOverZZ()[0];

   secretKey.GenSecKey(w);
   // actually generate a secret key with Hamming weight w

   addSome1DMatrices(secretKey);
   cout << "Generated key" << endl;


   EncryptedArray ea(context, G);
   // constuct an Encrypted array object ea that is
   // associated with the given context and the polynomial G

   long nslots = ea.size();

   cout << nslots;

   vector<long> v1;

   long a1 = 10;
   for(int i = 0 ; i < nslots; i++) {
       long remainder = a1%2;
       a1 = a1/2;
       v1.push_back(remainder);
   }
   //std::reverse(v1.begin(),v1.end());
   Ctxt ct1(publicKey);
   ea.encrypt(ct1, publicKey, v1);

   vector<long> v2;
   Ctxt ct2(publicKey);
   
   long a2 = 15;
   for(int i = 0 ; i < nslots; i++) {
       long remainder = a2%2;
       a2 = a2/2;
       v2.push_back(remainder);
   }
   ea.encrypt(ct2, publicKey, v2);

     // On the public (untrusted) system we
   // can now perform our computation

   Ctxt ctSum = ct1;
   Ctxt ctProd = ct1;

   ctSum += ct2;
   ctProd *= ct2;


    Ctxt ctSum1 = ct1[0]; //hello
    ctSum1 += ct2[0];  //hello

    vector<long> res;
    vector<long> res1; // hello
    ea.decrypt(ctSum, secretKey, res);

    ea.decrypt(ctSum1, secretKey, res1); //hello

    cout << "All computations are modulo " << p << "." << endl;
    for(int i = 0; i < res.size(); i ++) {
        cout << v1[i] << " + " << v2[i] << " = " << res[i] << endl;
    }

    ea.decrypt(ctProd, secretKey, res);
    for(int i = 0; i < res.size(); i ++) {
        cout << v1[i] << " * " << v2[i] << " = " << res[i] << endl;
    }

    vector<long> res;
    ea.decrypt(ctSum, secretKey, res);
    

    return 0;
}
