#include "CryptoCL/Block/BlockCipher.h"

namespace CryptoCL {
	namespace Block {
		BlockCipher::BlockCipher( const Mode::BlockMode mode, const DataArray& iv ) : mMode( mode ), mInitialisationVector( iv ) {
		
		}
				
		const Mode::BlockMode& BlockCipher::Mode() const {
			return mMode;
		}
		
		const DataArray& BlockCipher::InitialisationVector() const {
			return mInitialisationVector;
		}
	}
}
