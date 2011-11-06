#include "CryptoCL/Block/AES/Reference.h"

#include <iomanip>
#include <iostream>

namespace CryptoCL {
	namespace Block {
		namespace AES {
			/* Public Functions */
			Reference::Reference( const Mode::BlockMode mode, const DataArray& iv ) 
				: AESBlockCipher( mode, iv ), mState( 0 ) {
			
			}
			
			const DataArray Reference::Encrypt( const DataArray& data ) {
				DataArray result, lData( data.begin(), data.end() );
				
				const unsigned int blocks = lData.size() / 16;
				for( unsigned int i = 0; i < blocks; i++ ){
					const unsigned int sPos = i * 16;
					
					mState.clear();
					mState.insert( mState.end(), lData.begin() + sPos, lData.begin() + sPos + 16 );
					
					if( mMode == Mode::CipherBlockChaining ) {
						if( i == 0 ) {
							for(unsigned int s = 0; s < 16; s++ ) mState[s] ^= mInitialisationVector[s];
						}else{
							for(unsigned int s = 0; s < 16; s++ ) mState[s] ^= result[sPos-16+s];
						}
					}
					
					AddRoundKey( 0 );
					
					for( unsigned int j = 1; j < mKey.Rounds(); j++ ){
						SubBytes();
						ShiftRows();
						MixColumns();
						AddRoundKey( j );
					}
					
					SubBytes();
					ShiftRows();
					AddRoundKey( mKey.Rounds() );
					
					result.insert( result.end(), mState.begin(), mState.end() );
				}
				
				return result;
			}
			
			const DataArray Reference::Decrypt( const DataArray& data ) {
				DataArray result, lData( data.begin(), data.end() );
				
				const unsigned int blocks = lData.size() / 16;
				for( unsigned int i = 0; i < blocks; i++ ){
					const unsigned int sPos = i * 16;
					
					mState.clear();
					mState.insert( mState.end(), lData.begin() + sPos, lData.begin() + sPos + 16 );
					
					AddRoundKey( mKey.Rounds() );
					
					for( unsigned int j = mKey.Rounds() - 1; j > 0; j-- ){
						InvShiftRows();
						InvSubBytes();
						AddRoundKey( j );
						InvMixColumns();
					}
					
					InvSubBytes();
					InvShiftRows();
					AddRoundKey( 0 );

					if( mMode == Mode::CipherBlockChaining ) {
						if( i == 0 ) {
							for(unsigned int s = 0; s < 16; s++ ) mState[s] ^= mInitialisationVector[s];
						}else{
							for(unsigned int s = 0; s < 16; s++ ) mState[s] ^= data[sPos-16+s];
						}
					}
					
					result.insert( result.end(), mState.begin(), mState.end() );
				}
				
				return result;
			}
			
			/* General Helper Functions */
			unsigned char gmul(unsigned char a, unsigned char b) {
				unsigned char p = 0;
				unsigned char hi_bit_set;
				for(unsigned char counter = 0; counter < 8; counter++) {
					if((b & 1) == 1) 
						p ^= a;
					hi_bit_set = (a & 0x80);
					a <<= 1;
					if(hi_bit_set == 0x80) 
						a ^= 0x1b;		
					b >>= 1;
				}
				return p;
			}
			
			/* Protected Functions */
			void Reference::AddRoundKey( const unsigned int round ) {
				const DataArray RoundKey = mKey.Value( round );
				
				for( unsigned int i = 0; i < mState.size(); i++ ){
					mState[i] = mState[i] ^ RoundKey[i];
				}
			}
					
			/* Encryption Helpers */
			void Reference::SubBytes() {
				for( unsigned int i = 0; i < mState.size(); i++ ){
					mState[i] = SBox[mState[i]];
				}
			}
			
			void Reference::ShiftRows() {
				const DataArray TempState( mState.begin(), mState.end() );
				for (unsigned int i = 0; i < 16; i++) {
					unsigned int row = i % 4;
					unsigned int k = (i + (row * 4)) % 16;
					mState[i] = TempState[k];
				}
			}
			
			void MixColumn( DataArray& column, const unsigned int pos ) {
				const unsigned char a = gmul(column[pos+0],2) ^ gmul(column[pos+3],1) ^ gmul(column[pos+2],1) ^ gmul(column[pos+1],3);
				const unsigned char b = gmul(column[pos+1],2) ^ gmul(column[pos+0],1) ^ gmul(column[pos+3],1) ^ gmul(column[pos+2],3);
				const unsigned char c = gmul(column[pos+2],2) ^ gmul(column[pos+1],1) ^ gmul(column[pos+0],1) ^ gmul(column[pos+3],3);
				const unsigned char d = gmul(column[pos+3],2) ^ gmul(column[pos+2],1) ^ gmul(column[pos+1],1) ^ gmul(column[pos+0],3);
				
				column[pos+0] = a; column[pos+1] = b; column[pos+2] = c; column[pos+3] = d;
			}

			void OptimizedMixColumn( DataArray& column, const unsigned int pos ) {
				const unsigned char cZero = gmul(column[pos+0],2), cOne = gmul(column[pos+1],2), cTwo = gmul(column[pos+2],2), cThree = gmul(column[pos+3],2);
				
				const unsigned char a = cZero  ^ column[pos+3] ^ column[pos+2] ^ cOne   ^ column[pos+1];
				const unsigned char b = cOne   ^ column[pos+0] ^ column[pos+3] ^ cTwo   ^ column[pos+2];
				const unsigned char c = cTwo   ^ column[pos+1] ^ column[pos+0] ^ cThree ^ column[pos+3];
				const unsigned char d = cThree ^ column[pos+2] ^ column[pos+1] ^ cZero  ^ column[pos+0];
				
				column[pos+0] = a; column[pos+1] = b; column[pos+2] = c; column[pos+3] = d;
			}

			void Reference::MixColumns() {
				OptimizedMixColumn( mState, 0 );
				OptimizedMixColumn( mState, 4 );
				OptimizedMixColumn( mState, 8 );
				OptimizedMixColumn( mState, 12 );
			}
			
			/* Decryption Helpers */
			void Reference::InvSubBytes() {
				for( unsigned int i = 0; i < mState.size(); i++ ){
					mState[i] = InvSBox[mState[i]];
				}
			}
			
			void Reference::InvShiftRows() {
				const DataArray TempState( mState.begin(), mState.end() );
				for (unsigned int i = 0; i < 16; i++) {
					unsigned int row = i % 4;
					unsigned int k = (i - (row * 4)) % 16;
					mState[i] = TempState[k];
				}
			}
			
			void InvMixColumn( DataArray& column, const unsigned int pos ){
				const unsigned char a = gmul(column[pos+0],14) ^ gmul(column[pos+3],9) ^ gmul(column[pos+2],13) ^ gmul(column[pos+1],11);
				const unsigned char b = gmul(column[pos+1],14) ^ gmul(column[pos+0],9) ^ gmul(column[pos+3],13) ^ gmul(column[pos+2],11);
				const unsigned char c = gmul(column[pos+2],14) ^ gmul(column[pos+1],9) ^ gmul(column[pos+0],13) ^ gmul(column[pos+3],11);
				const unsigned char d = gmul(column[pos+3],14) ^ gmul(column[pos+2],9) ^ gmul(column[pos+1],13) ^ gmul(column[pos+0],11);
					
				column[pos+0] = a; column[pos+1] = b; column[pos+2] = c; column[pos+3] = d;
			}

			void Reference::InvMixColumns() {
				InvMixColumn( mState, 0 );
				InvMixColumn( mState, 4 );
				InvMixColumn( mState, 8 );
				InvMixColumn( mState, 12 );
			}
		}
	}
}
