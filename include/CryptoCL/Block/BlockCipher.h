#ifndef CRYPTOCL_BLOCK_BLOCKCIPHER_H_
#define CRYPTOCL_BLOCK_BLOCKCIPHER_H_

#include "CryptoCL/Cipher.h"

namespace CryptoCL {
	namespace Block {
		namespace Mode {
			enum BlockMode {
				ElectronicCookBook, CipherBlockChaining
			};
		}
		
		class BlockCipher : public Cipher {
			protected:
				Mode::BlockMode mMode;
				DataArray mInitialisationVector;
			public:
				BlockCipher( const Mode::BlockMode mode = Mode::ElectronicCookBook, const DataArray& iv = DataArray() );
				
				const Mode::BlockMode& Mode() const;
				void Mode( const Mode::BlockMode& mode );
				
				const DataArray& InitialisationVector() const;
				void InitialisationVector( const DataArray& iv );
		};
	}
}

#endif // CRYPTOCL_BLOCK_BLOCKCIPHER_H_
