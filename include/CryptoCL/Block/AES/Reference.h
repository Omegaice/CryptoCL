#ifndef CRYPTOCL_AES_REFERENCE_H_
#define CRYPTOCL_AES_REFERENCE_H_

#include "CryptoCL/Block/AES/AESBlockCipher.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			class Reference : public AESBlockCipher {
				public:
					Reference( const Mode::BlockMode mode = Mode::ElectronicCookBook);
					
					const DataArray Encrypt( const DataArray& data, const CryptoCL::Key& key, const DataArray& iv = DataArray() ) const;
					const ArrayVector Encrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv = ArrayVector() ) const;
					
					const DataArray Decrypt( const DataArray& data, const CryptoCL::Key& key, const DataArray& iv = DataArray() ) const;
					const ArrayVector Decrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv = ArrayVector() ) const;
				protected:
					/* Block Functions */
					const DataArray EncryptBlock( const DataArray& block, const RoundKey& rkey ) const;
					const DataArray DecryptBlock( const DataArray& block, const RoundKey& rkey ) const;
					
					const DataArray XORBlock( const DataArray& a, const DataArray& b ) const;
					const DataArray AddRoundKey( const DataArray& block, const RoundKey& key, const unsigned int round ) const;
					
					/* Encryption Helpers */
					const DataArray SubBytes( const DataArray& block ) const;
					const DataArray ShiftRows( const DataArray& block ) const;
					const DataArray MixColumns( const DataArray& block ) const;
					
					/* Decryption Helpers */
					const DataArray InvSubBytes( const DataArray& block ) const;
					const DataArray InvShiftRows( const DataArray& block ) const;
					const DataArray InvMixColumns( const DataArray& block ) const;
			};
		}
	}
}

#endif // CRYPTOCL_AES_REFERENCE_H_
