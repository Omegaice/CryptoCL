#include "CryptoCL/AES/RoundKey.h"

#include <cassert>
#include <iostream>
#include "CryptoCL/AES/Base.h"

namespace CryptoCL {
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
	
			// Until we have b bytes of expanded key, we do the following to generate n more bytes of expanded key:
			unsigned int rConIteration = 1;
			while( mData.size() < roundKeySize ){
				const unsigned int prevStart = (int)mSize;
				const unsigned int prevEnd = (int)mSize - 4;
				
				// We do the following to create 4 bytes of expanded key
				
				// We create a 4-byte temporary variable, t
				// We assign the value of the previous four bytes in the expanded key to t
				DataArray RoundKey( mData.end() - 4, mData.end() );
				DataArray PreviousKey( mData.end() - prevStart, mData.end() - prevEnd );
				
				// We perform the key schedule core (see above) on t, with i as the rcon iteration value
				// We increment i by 1
				RoundKey = KeyScheduleCore( RoundKey, rConIteration++ );
				
				// We exclusive-or t with the four-byte block n bytes before the new expanded key.
				for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
				
				//This becomes the next 4 bytes in the expanded key
				mData.insert( mData.end(), RoundKey.begin(), RoundKey.end() );
				
				// We then do the following three times to create the next twelve bytes of expanded key:
				for( unsigned int i = 0; i < 3; i++){
					// We assign the value of the previous 4 bytes in the expanded key to t
					RoundKey = DataArray( mData.end() - 4, mData.end() );
					
					// We exclusive-or t with the four-byte block n bytes before the new expanded key.
					PreviousKey = DataArray( mData.end() - prevStart, mData.end() - prevEnd );
					for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
					
					//This becomes the next 4 bytes in the expanded key
					mData.insert( mData.end(), RoundKey.begin(), RoundKey.end() );
				}
				
				// If we are generating a 256-bit key, we do the following to generate the next 4 bytes of expanded key:
				if( mSize == Key::Bit256 ){
				
					//We assign the value of the previous 4 bytes in the expanded key to t
					RoundKey = DataArray( mData.end() - 4, mData.end() );
					
					//We run each of the 4 bytes in t through Rijndael's S-box
					for(int a = 0; a < 4; a++) RoundKey[a] = SBox[RoundKey[a]];
					
					//We exclusive-or t with the 4-byte block n bytes before the new expanded key.
					PreviousKey = DataArray( mData.end() - prevStart, mData.end() - prevEnd );
					for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
					
					//This becomes the next 4 bytes in the expanded key.
					mData.insert( mData.end(), RoundKey.begin(), RoundKey.end() );
				}
				
				// If we are generating a 192-bit key, we run the following steps twice. 
				if( mSize == Key::Bit192 ){
					for( unsigned int i = 0; i < 2; i ++ ){
						// We assign the value of the previous 4 bytes in the expanded key to t
						RoundKey = DataArray( mData.end() - 4, mData.end() );
						
						// We exclusive-or t with the four-byte block n bytes before the new expanded key. 
						PreviousKey = DataArray( mData.end() - prevStart, mData.end() - prevEnd );
						for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
						
						//This becomes the next 4 bytes in the expanded key.
						mData.insert( mData.end(), RoundKey.begin(), RoundKey.end() );
					}				
				}
				
				// If we are generating a 256-bit key, we run the following steps three times:
				if( mSize == Key::Bit256 ){
					for( unsigned int i = 0; i < 3; i ++ ){
						// We assign the value of the previous 4 bytes in the expanded key to t
						RoundKey = DataArray( mData.end() - 4, mData.end() );
						
						// We exclusive-or t with the four-byte block n bytes before the new expanded key. 
						PreviousKey = DataArray( mData.end() - prevStart, mData.end() - prevEnd );
						for(int a = 0; a < 4; a++) RoundKey[a] ^= PreviousKey[a];
						
						//This becomes the next 4 bytes in the expanded key.
						mData.insert( mData.end(), RoundKey.begin(), RoundKey.end() );
					}				
				}
			}
			
			if( mData.size() > roundKeySize ) mData.resize( roundKeySize );
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
		
		const DataArray RoundKey::Rotate( const DataArray& input ){
			DataArray retVal( 4 );
			
			retVal[0] = input[1];
			retVal[1] = input[2];
			retVal[2] = input[3];
			retVal[3] = input[0];
			
			return retVal;
		}

		const DataArray RoundKey::KeyScheduleCore( const DataArray& input, const unsigned int iteration ) {
			DataArray output = Rotate( input );
			
			output[0] = SBox[output[0]];
			output[1] = SBox[output[1]];
			output[2] = SBox[output[2]];
			output[3] = SBox[output[3]];
			
			output[0] ^= Rcon[iteration];
				
			return output;
		}
	}
}
