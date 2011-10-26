#ifndef CRYPTOCL_AES_ROUNDKEY_H_
#define CRYPTOCL_AES_ROUNDKEY_H_

#include <vector>
#include "CryptoCL/AES/Base.h"

namespace CryptoCL {
	namespace AES {
		namespace Key {
			enum KeySize{ None = 0, Bit128 = 16, Bit192 = 24, Bit256 = 32 };
		}
		
		class RoundKey {
			private:
				Key::KeySize mSize;
				DataArray mData;
			public:
				RoundKey();
				RoundKey( const DataArray& key );
				
				void Initialise( const DataArray& key );
				
				unsigned int Rounds() const;
				
				const Key::KeySize Size() const;
				const DataArray Value() const;
				const DataArray Value( const unsigned int i ) const;
			private:
				const DataArray KeyScheduleCore( const DataArray& input, const unsigned int iteration );
		};
	}
}

#endif // CRYPTOCL_AES_ROUNDKEY_H_