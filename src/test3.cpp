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


	// a fuction that compares two ctxts encrypted as arrays of binary ctxts
Ctxt equal_c(vector<Ctxt>  c1, vector<Ctxt> c2){




	// intilize 
	Ctxt equal =  c1[0]; 

	equal.addCtxt(c2[0]);


	equal.addConstant(to_ZZX(1));

	// loop through all bits

	for(int i = 1 ; i < 8; i++) {
		Ctxt temp =  c1[i]; 	//+ c2[0] + onecv[0];
		temp.addCtxt(c2[i]);
		temp.addConstant(to_ZZX(1));
		equal.multiplyBy(temp);

	}
	// return the product
	return equal;
	
}


int main(int argc, char** argv) {

	

	 long m=0, p=2, r=1; 	// Native plaintext space
						// Computations will be 'modulo p'
	 long L=16;			 	// Levels
	 long c=3;			  	// Columns in key switching matrix
	 long w=64;			 	// Hamming weight of secret key
	 long d=0;
	long security = 128;

	m = FindM(security,L,c,p, d, 0, 0);
	FHEcontext context(m, p, r);
	buildModChain(context, L);
	FHESecKey sk(context);
	sk.GenSecKey(64);
	addSome1DMatrices(sk);
	FHEPubKey pk = sk;
	
		//Ctxt ctxt(pk);
		//ZZX plain = to_ZZX(9);
		//pk.Encrypt(ctxt, plain); 	// ctxt = 9
		//ctxt.mulByConstant(to_ZZX(2));
	/*ctxt.addConstant(to_ZZX(10)); 	// ctxt == 19
	
	ctxt.multiplyBy(ctxt); 	//ctxt = 19*19 = 361
	sk.Decrypt(plain,ctxt);
	cout << plain[0] << "\n";

*/

	vector<long> v1;
	vector<Ctxt> ct1v;



	// encoding the first number as array of ctxts
	long a1 = 10;
	for(int i = 0 ; i < 8; i++) {
		 ZZX remainder = to_ZZX(a1%2);
		 a1 = a1/2;
		 Ctxt ctxt(pk);
		 pk.Encrypt(ctxt, remainder); 
		 ct1v.push_back(ctxt);
	}



		vector<long> v2;
	vector<Ctxt> ct2v;

	// encoding the second number as array of ctxts
	long a2 = 10;
	for(int i = 0 ; i < 8; i++) {
		 ZZX remainder = to_ZZX(a2%2);
		 a2 = a2/2;
		 Ctxt ctxt(pk);
		 pk.Encrypt(ctxt, remainder); 
		 ct2v.push_back(ctxt);
	}

	// comparing the resutls

	Ctxt result = equal_c(ct1v, ct2v);


	// decrypting and printing the resutl
	ZZX plain;
	sk.Decrypt(plain,result);
	cout << plain[0] << "\n";
	 return 0;
}
