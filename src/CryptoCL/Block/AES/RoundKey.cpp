#include "CryptoCL/Block/AES/RoundKey.h"

#include <cassert>
#include <iostream>
#include "CryptoCL/Block/AES/AESBlockCipher.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			RoundKey::RoundKey() 
				: mSize( Key::None ), mData( 0 ) { 
			
			}
			
			RoundKey::RoundKey( const DataArray& key ) 
				: mSize( Key::None ), mData( 0 ) {
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
					if( mSize == Key::Bit256 && eSize % (int)mSize == 16 ) for(int a = 0; a < 4; a++) RoundKey[a] = AESBlockCipher::SBox[RoundKey[a]];
					
					/* Xor Result */
					for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
					
					/* Store Data */
					mData.insert( mData.end(), RoundKey.begin(), RoundKey.end() );
				}
			}
			
			unsigned int RoundKey::Rounds() const {
				unsigned int retVal = 0;
				
				switch ( mSize ) {
					case Key::None:
						retVal = 0;
						break;
					case Key::Bit128:
						retVal = 10;
						break;
					case Key::Bit192:
						retVal = 12;
						break;
					case Key::Bit256:
						retVal = 14;
						break;
				}
				
				return retVal;
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
				
				output[0] = AESBlockCipher::SBox[input[1]] ^ AESBlockCipher::Rcon[iteration];
				output[1] = AESBlockCipher::SBox[input[2]];
				output[2] = AESBlockCipher::SBox[input[3]];
				output[3] = AESBlockCipher::SBox[input[0]];
					
				return output;
			}
		}
	}
}
