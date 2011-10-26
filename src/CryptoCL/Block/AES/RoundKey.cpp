#include "CryptoCL/Block/AES/RoundKey.h"

#include <cassert>
#include <iostream>
#include "CryptoCL/Block/AES/Base.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			RoundKey::RoundKey() : mSize( Key::None ) { 
			
			}
			
			RoundKey::RoundKey( const DataArray& key ) {
				Initialise( key );
			}
					
			void RoundKey::Initialise( const DataArray& key ) {
				const unsigned int keySize = key.size();
				assert( keySize == 16 || keySize == 24 || keySize == 32 );
				
				// Save KeySize
				mSize = static_cast<Key::KeySize>( keySize );
				
				// Calculate Round Key Size 
				const unsigned int roundKeySize = 16 * ( Rounds() + 1 );
				
				// First Round
				mData.clear();
				mData.insert( mData.end(), key.begin(), key.end() );
				
				unsigned int rConIteration = 1;
				while( mData.size() < roundKeySize ){
					const unsigned int eSize = mData.size();
					const unsigned int prevStart = (int)mSize, prevEnd = (int)mSize - 4;
					
					DataArray RoundKey( mData.end() - 4, mData.end() );
					const DataArray PreviousKey( mData.end() - prevStart, mData.end() - prevEnd );
					
					/* Complex Calculation */
					if( eSize % (int)mSize == 0 ) RoundKey = KeyScheduleCore( RoundKey, rConIteration++ );
					
					/* Extra SBox */
					if( mSize == Key::Bit256 && eSize % (int)mSize == 16 ) for(int a = 0; a < 4; a++) RoundKey[a] = Base::SBox[RoundKey[a]];
					
					/* Xor Result */
					for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
					
					/* Store Data */
					mData.insert( mData.end(), RoundKey.begin(), RoundKey.end() );
				}
			}
			
			unsigned int RoundKey::Rounds() const {
				switch ( mSize ) {
					case Key::None:
						return 0;
						break;
					case Key::Bit128:
						return 10;
						break;
					case Key::Bit192:
						return 12;
						break;
					case Key::Bit256:
						return 14;
						break;
				}
			}
			
			const Key::KeySize RoundKey::Size() const {
				return mSize;
			}
			
			const DataArray RoundKey::Value() const {
				return mData;
			}
			
			const DataArray RoundKey::Value( const unsigned int i ) const {
				if( mSize == Key::None ) return std::vector<unsigned char>();
						
				const unsigned int iPos = i * 16;
				return std::vector<unsigned char>( mData.begin() + iPos, mData.begin() + iPos + 16 );
			}
			
			// Rotate array and substitute sbox values
			const DataArray RoundKey::KeyScheduleCore( const DataArray& input, const unsigned int iteration ) {
				DataArray output( 4 );
				
				output[0] = Base::SBox[input[1]] ^ Base::Rcon[iteration];
				output[1] = Base::SBox[input[2]];
				output[2] = Base::SBox[input[3]];
				output[3] = Base::SBox[input[0]];
					
				return output;
			}
		}
	}
}
