#include "CryptoCL/Block/BlockCipher.h"

#include <cmath>

namespace CryptoCL {
	namespace Block {
		BlockCipher::BlockCipher( const Mode::BlockMode mode ) : mMode( mode ) {
		
		}
				
		const Mode::BlockMode& BlockCipher::Mode() const {
			return mMode;
		}
		
		
		void BlockCipher::Mode( const Mode::BlockMode& mode ) {
			mMode = mode;
		}
		
		const std::vector<DataArray> BlockCipher::SplitArray( const DataArray& array, const unsigned int size ) const{
				const unsigned int arraySize = array.size();
				const unsigned int blockCount = std::ceil( (double)arraySize / (double)size ); 
							
				std::vector<DataArray> retVal( blockCount );
				
				unsigned int block = 0;
				for( unsigned int i = 0; i < arraySize; i++ ){
						if( ( i != 0 ) && ( i % size == 0 ) )block++;
						
						retVal[block].push_back( array[i] );
				}
				
				return retVal;
		}
	}
}
