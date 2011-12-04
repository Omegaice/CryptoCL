#include "CryptoCL/Block/AES/RoundKey.h"

#include <cassert>
#include <iostream>
#include "CryptoCL/Block/AES/AESBlockCipher.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			RoundKey::RoundKey( const DataArray& key ) 
				: CryptoCL::Key( key ), mSize( static_cast<AES::Key::KeySize>( key.size() ) ), mRounds( GenerateKey( mKey ) ) {
			}
			
			unsigned int RoundKey::Rounds() const {
				unsigned int retVal = 0;
				
				switch ( mSize ) {
					case AES::Key::None:
						retVal = 0;
						break;
					case AES::Key::Bit128:
						retVal = 10;
						break;
					case AES::Key::Bit192:
						retVal = 12;
						break;
					case AES::Key::Bit256:
						retVal = 14;
						break;
				}
				
				return retVal;
			}
			
			const Key::KeySize RoundKey::Size() const {
				return mSize;
			}
			
			const DataArray RoundKey::Value() const {
				return mRounds;
			}
			
			const DataArray RoundKey::Value( const unsigned int i ) const {
				if( mSize == AES::Key::None ) return std::vector<unsigned char>();
						
				const unsigned int iPos = i * 16;
				return std::vector<unsigned char>( mRounds.begin() + iPos, mRounds.begin() + iPos + 16 );
			}
			
			RoundKey& RoundKey::operator=( const RoundKey& other ) {
				return *this;
			}
			
			const DataArray RoundKey::GenerateKey( const DataArray& key ) const {
				assert( mSize == 16 || mSize == 24 || mSize == 32 );
				
				DataArray result( key );
		
				const unsigned int roundKeySize = 16 * ( Rounds() + 1 );
								
				unsigned int rConIteration = 1;
				while( result.size() < roundKeySize ){
					const unsigned int eSize = result.size();
					const unsigned int prevStart = (int)mSize, prevEnd = (int)mSize - 4;
					
					DataArray RoundKey( result.end() - 4, result.end() );
					const DataArray PreviousKey( result.end() - prevStart, result.end() - prevEnd );
					
					/* Complex Calculation */
					if( eSize % (int)mSize == 0 ) RoundKey = KeyScheduleCore( RoundKey, rConIteration++ );
					
					/* Extra SBox */
					if( mSize == AES::Key::Bit256 && eSize % (int)mSize == 16 ) for(int a = 0; a < 4; a++) RoundKey[a] = AESBlockCipher::SBox[RoundKey[a]];
					
					/* Xor Result */
					for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
					
					/* Store Data */
					result.insert( result.end(), RoundKey.begin(), RoundKey.end() );
				}
				
				return result;
			}
			
			const DataArray RoundKey::KeyScheduleCore( const DataArray& input, const unsigned int iteration ) const {
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
