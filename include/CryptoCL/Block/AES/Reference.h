#ifndef CRYPTOCL_AES_REFERENCE_H_
#define CRYPTOCL_AES_REFERENCE_H_

#include "CryptoCL/Block/AES/AESBlockCipher.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			class Reference : public AESBlockCipher {
				protected:	
					DataArray mState;
				public:
					Reference( const Mode::BlockMode mode = Mode::ElectronicCookBook, const DataArray& iv = DataArray() );
					
					const DataArray Encrypt( const DataArray& data );
					const DataArray Decrypt( const DataArray& data );
				protected:
					void AddRoundKey( const unsigned int round );
					
					/* Encryption Helpers */
					void SubBytes();
					void ShiftRows();
					void MixColumns();
					
					/* Decryption Helpers */
					void InvSubBytes();
					void InvShiftRows();
					void InvMixColumns();
			};
		}
	}
}

#endif // CRYPTOCL_AES_REFERENCE_H_
