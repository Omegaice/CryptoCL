#ifndef CRYPTOCL_AES_REFERENCE_H_
#define CRYPTOCL_AES_REFERENCE_H_

#include "CryptoCL/AES/Base.h"
#include "CryptoCL/AES/RoundKey.h"

namespace CryptoCL {
	namespace AES {
		class Reference {
			protected:	
				DataArray mState;
				RoundKey mKey;
			public:
				Reference();
				Reference( const RoundKey& key );
				
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

#endif // CRYPTOCL_AES_REFERENCE_H_
