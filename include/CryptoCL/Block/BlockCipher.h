#ifndef CRYPTOCL_BLOCK_BLOCKCIPHER_H_
#define CRYPTOCL_BLOCK_BLOCKCIPHER_H_

#include "CryptoCL/Cipher.h"

namespace CryptoCL {
	namespace Block {
		namespace Mode {
			enum BlockMode { ElectronicCookBook, CipherBlockChaining };
		}
		
		class BlockCipher : public Cipher {
			protected:
				Mode::BlockMode mMode;
			public:
				BlockCipher( const Mode::BlockMode mode = Mode::ElectronicCookBook );
				
				const Mode::BlockMode& Mode() const;
				void Mode( const Mode::BlockMode& mode );
			protected:
				const std::vector<DataArray> SplitArray( const DataArray& array, const unsigned int size ) const;
		};
	}
}

#endif // CRYPTOCL_BLOCK_BLOCKCIPHER_H_
