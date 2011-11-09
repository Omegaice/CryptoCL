#include "CryptoCL/Block/BlockCipher.h"

namespace CryptoCL {
	namespace Block {
		BlockCipher::BlockCipher( const Mode::BlockMode mode, const DataArray& iv ) : mMode( mode ), mInitialisationVector( iv ) {
		
		}
				
		const Mode::BlockMode& BlockCipher::Mode() const {
			return mMode;
		}
		
		
		void BlockCipher::Mode( const Mode::BlockMode& mode ) {
			mMode = mode;
		}
		
		const DataArray& BlockCipher::InitialisationVector() const {
			return mInitialisationVector;
		}
		
		void BlockCipher::InitialisationVector( const DataArray& iv ) {
			mInitialisationVector = iv;
		}
	}
}
