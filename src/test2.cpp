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

Ctxt equal_c(vector<Ctxt>&  c1, vector<Ctxt>& c2, vector<Ctxt>& onecv){

	
	Ctxt equal =  c1[0]; //+ c2[0] + onecv[0];
	equal.addCtxt(c2[0]);
	equal.addCtxt(onecv[0]);

	for(int i = 1 ; i < 64; i++) {
		Ctxt temp =  c1[i]; //+ c2[0] + onecv[0];
		temp.addCtxt(c2[i]);
		temp.addCtxt(onecv[i]);
		equal.multiplyBy(temp);

	}
 
	return equal;
	
}

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
   vector<Ctxt> ct1v;

   long a1 = 10;
   for(int i = 0 ; i < 64; i++) {
       long remainder = a1%2;
       a1 = a1/2;
       vector<long> v1t;
       v1t.push_back(remainder);
       Ctxt ct1t(publicKey);
       ea.encrypt(ct1t, publicKey, v1t);
       ct1v.push_back(ct1t);
   }

   vector<long> v2;
   vector<Ctxt> ct2v;

   long a2 = 15;
   for(int i = 0 ; i < 64; i++) {
       long remainder = a2%2;
       a2 = a2/2;
       vector<long> v2t;
       v2t.push_back(remainder);
       Ctxt ct2t(publicKey);
       ea.encrypt(ct2t, publicKey, v2t);
       ct2v.push_back(ct2t);
   }


   vector<Ctxt> onescv;

   for(int i = 0 ; i < 64; i++) {
       long remainder = 1;
       vector<long> one;
       one.push_back(remainder);
       Ctxt onet(publicKey);
       ea.encrypt(onet, publicKey, one);
       onescv.push_back(onet);
   }


   Ctxt equal = equal_c(ct1v, ct2v, onescv);
  
    vector<long> res; // hello
    ea.decrypt(equal, secretKey, res);



    cout << "equal? " << res[0] << "." << endl;

    return 0;
}
