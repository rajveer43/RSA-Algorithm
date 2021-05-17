/*$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
---------------------------------------------------------------------------------------------------------
------------------------------                                       ------------------------------------
------------------------------      RSA ALGORITHM IMPLEMENTATION     ------------------------------------
------------------------------                                       ------------------------------------
---------------------------------------------------------------------------------------------------------
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$*/

/*
    Reference of Algorithm : Data Communications and Networking By Behrouz A.Forouzan(4th Edition)
    Code written by : RAJVEER RATHOD(19CP074)
    Group : 6
    Other group members : VATSAL DHUPELIA(19CP076)
                          AKSHAT TRIVEDI(19CP075)
    Purpose of Code : Demonstration of Encryption and Ecryption of string using RSA Algorithm
    Platform : WINDOWS-10 64-Bit
*/

//Neccessary header files
#include <iostream>
#include <cmath>
#include <cstring>

// Alphabet values used for ASCII converstion:
static
const char Alphabet[26] = { 
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
	'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
	'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' 
	};

//structure 
struct Primes
{
	double p, q;
};

//namespace to set private and public key
namespace Keys
{
	struct publicKey
	{
		double n, e;
	};

	struct privateKey
	{
		double d;
	};
};

//class
class RSA
{
	public:
		RSA(int, int);
		
		double gcd(double, double);
		
		void exponent();
		
		void privateKey();
		
		void convertToNumbers(char*);
		
		void encrypt();
		
		void decrypt();
		
		int modular_pow(int, int, int);
	
		void print();

	private:
		Primes primes;
		Keys::publicKey pubKey;
		Keys::privateKey privKey;
	
		// Array containing the plaintext/ciphertext:
		int *buffer = new int[512];
		int size = 0;
		double phi;
};

RSA::RSA(int _p, int _q)
{
	// Set the values for p and q
	primes.p = _p;
	primes.q = _q;

	// Set n = p *q
	pubKey.n = primes.p *primes.q;

	// Phi = (p-1) *(q-1)
	phi = (primes.p - 1) *(primes.q - 1);
}

double RSA::gcd(double a, double b)
{
	double temp;
	while (true)
	{
		temp = (int) a % (int) b;
		if (temp == 0)
		{
			return b;
		}

		a = b;
		b = temp;
	}
}

void RSA::exponent()
{
	// Set the exponent e:
	std::cout << "Enter a value for exponent: ";
	double _e;
	std::cin >> _e;
	
	//check whether the exponent is within given range or not
	if (_e < 1)
	{ 
		std::cout << "Exponent must be greater than 1.\n";
		exponent();
	}
	else if (_e > phi) 
	{
		std::cout << "Exponent must be smaller than phi.\n";
		exit(1);
	}

	// Verify that e is valid:
	while (_e < phi)
	{
		if (gcd(_e, phi) == 1) 
			break;
		else
			 _e++;
	}

	pubKey.e = _e;
}

void RSA::privateKey()
{
	int i = 1;
	float temp;
	while (1)
	{
		temp = ((phi *i) + 1) / pubKey.e;
		//std::cout<<"inside the while, temp,i = "<<temp<<","<<i<<"\n";

		if (std::fmod(temp, 1) == 0)
		{
			//std::cout<<(int)temp<<"  "<<temp;
			privKey.d = (int) floor(temp);
			break;
		}

		i++;
	}
}


int RSA::modular_pow(int base, int exponent, int modulus)
{
	int result = 1;
	while (exponent > 0)
	{
		if (exponent % 2 == 1)
			result = (result *base) % modulus;
		exponent = exponent >> 1;
		base = (base *base) % modulus;
	}

	return result;
}

void RSA::encrypt()
{
	// Read the buffer array, encrypt each character:
	unsigned long long int ctext;
	std::cout << "Encrypted ciphertext: ";
	for (int i = 0; i < size; i++)
	{
		ctext = modular_pow(buffer[i], pubKey.e, pubKey.n);
		buffer[i] = ctext;
		std::cout << ctext;
	}

	std::cout << std::endl;
}

void RSA::decrypt()
{
	// Read the ciphertext from buffer array, decrypt each character:
	unsigned long long int ptext;
	std::cout << "Decrypted plaintext: ";
	for (int i = 0; i < size; i++)
	{
		ptext = modular_pow(buffer[i], privKey.d, pubKey.n);
		buffer[i] = ptext;
		std::cout << Alphabet[ptext];
	}

	std::cout << std::endl;
}

void RSA::convertToNumbers(char *plaintext)
{
	// Convert characters to ASCII decimals:
	for (int i = 0; i < strlen(plaintext); i++)
	{
		buffer[i] = plaintext[i] - 65;
	}

	size = strlen(plaintext);
}

void RSA::print()
{
	std::cout << "P = " << primes.p << "\n" << "q =" << primes.q << "\nn = " 
	<< pubKey.n << "\nphi = " << phi << "\ne =" << pubKey.e << "\nd= " 
	<< privKey.d << "\n";
}

int main()
{
	// Promt the user to enter two prime numbers:
	std::cout << "Enter two prime numbers (separated with whitespace): ";
	int p, q;
	std::cin >> p >> q;

	// Initiate the program, set the exponent and generate the private key:
	RSA rsa(p, q);
	rsa.exponent();
	rsa.privateKey();
	rsa.print();

	// Promt the user to enter a plaintext message:
	std::cout << "Enter a text message: ";
	char *plaintext = new char[512];
	std::cin >> plaintext;

	// Convert the plaintext characters into ASCII decimals:
	rsa.convertToNumbers(plaintext);

	// Run the encryption and decryption functions:
	rsa.encrypt();
	rsa.decrypt();
	return 0;
}
