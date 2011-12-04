#ifndef CRYPTOCL_AES_ROUNDKEY_H_
#define CRYPTOCL_AES_ROUNDKEY_H_

#include <vector>
#include "CryptoCL/Cipher.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			namespace Key {
				enum KeySize{ None = 0, Bit128 = 16, Bit192 = 24, Bit256 = 32 };
			}
			
			class RoundKey : public CryptoCL::Key {
				private:
					const AES::Key::KeySize mSize;
					const DataArray mRounds;
				public:
					RoundKey( const DataArray& key );
					
					unsigned int Rounds() const;
					
					const AES::Key::KeySize Size() const;
					const DataArray Value() const;
					const DataArray Value( const unsigned int i ) const;
				private:
					RoundKey& operator=( const RoundKey& other );
					
					const DataArray GenerateKey( const DataArray& key ) const;
					const DataArray KeyScheduleCore( const DataArray& input, const unsigned int iteration ) const;
			};
		}
	}
}

#endif // CRYPTOCL_AES_ROUNDKEY_H_