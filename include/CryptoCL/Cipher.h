#ifndef CRYPTOCL_CIPHER_H_
#define CRYPTOCL_CIPHER_H_

#include <vector>

namespace CryptoCL {
	typedef std::vector<unsigned char> DataArray;		
	
	struct Cipher {
		Cipher() {}
		virtual ~Cipher() {}
		
		virtual const DataArray Encrypt( const DataArray& data ) = 0;
		virtual const DataArray Decrypt( const DataArray& data ) = 0;
	};
}

#endif // CRYPTOCL_CIPHER_H_
