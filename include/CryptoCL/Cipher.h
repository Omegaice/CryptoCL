#ifndef CRYPTOCL_CIPHER_H_
#define CRYPTOCL_CIPHER_H_

#include <vector>
#include "CryptoCL/Key.h"

namespace CryptoCL {
	typedef std::vector<const Key*> KeyVector;
	typedef std::vector<DataArray> ArrayVector;
	
	struct Cipher {
		Cipher() {}
		virtual ~Cipher() {}
		
		virtual const DataArray Encrypt( const DataArray& data, const Key& key, const DataArray& iv = DataArray() ) const = 0;
		virtual const ArrayVector Encrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv = ArrayVector() ) const = 0;
		
		virtual const DataArray Decrypt( const DataArray& data, const Key& key, const DataArray& iv = DataArray() ) const = 0;
		virtual const ArrayVector Decrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv = ArrayVector() ) const = 0;
	};
}

#endif // CRYPTOCL_CIPHER_H_
