#ifndef CRYPTOCL_AES_REFERENCE_H_
#define CRYPTOCL_AES_REFERENCE_H_

#include "CryptoCL/Block/AES/AESBlockCipher.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			class Reference : public AESBlockCipher {
				public:
					Reference( const Mode::BlockMode mode = Mode::ElectronicCookBook, const DataArray& iv = DataArray() );
					
					const DataArray Encrypt( const DataArray& data );
					const DataArray Decrypt( const DataArray& data );
				protected:
					/* Block Functions */
					const DataArray Encrypt( const DataArray& block, const RoundKey& rkey );
					const DataArray Decrypt( const DataArray& block, const RoundKey& rkey );
					
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
