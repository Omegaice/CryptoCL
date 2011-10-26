#include "CryptoCL/Block/AES/Reference.h"

#include <iomanip>
#include <iostream>

namespace CryptoCL {
	namespace Block {
		namespace AES {
			/* Public Functions */
			const DataArray Reference::Encrypt( const DataArray& data ) {
				DataArray result, lData( data.begin(), data.end() );
				
				const unsigned int blocks = lData.size() / 16;
				for( unsigned int i = 0; i < blocks; i++ ){
					const unsigned int sPos = i * 16;
					
					mState.clear();
					mState.insert( mState.end(), lData.begin() + sPos, lData.begin() + sPos + 16 );
					
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
			
			DataArray MixColumn( const DataArray& column ) {
				DataArray result( 4 );
				
				result[0] = gmul(column[0],2) ^ gmul(column[3],1) ^ gmul(column[2],1) ^ gmul(column[1],3);
				result[1] = gmul(column[1],2) ^ gmul(column[0],1) ^ gmul(column[3],1) ^ gmul(column[2],3);
				result[2] = gmul(column[2],2) ^ gmul(column[1],1) ^ gmul(column[0],1) ^ gmul(column[3],3);
				result[3] = gmul(column[3],2) ^ gmul(column[2],1) ^ gmul(column[1],1) ^ gmul(column[0],3);
				
				return result;
			}

			void Reference::MixColumns() {
				for( unsigned int col = 0; col < 4; col++ ){
					DataArray column( 4 );
					column[0] = mState[col * 4 + 0];
					column[1] = mState[col * 4 + 1];
					column[2] = mState[col * 4 + 2];
					column[3] = mState[col * 4 + 3];
					
					const DataArray result = MixColumn( column );
					
					mState[col * 4 + 0] = result[0];
					mState[col * 4 + 1] = result[1];
					mState[col * 4 + 2] = result[2];
					mState[col * 4 + 3] = result[3];
				}
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
			
			DataArray InvMixColumn( const DataArray& column ){
				DataArray result( 4 );

				result[0] = gmul(column[0],14) ^ gmul(column[3],9) ^ gmul(column[2],13) ^ gmul(column[1],11);
				result[1] = gmul(column[1],14) ^ gmul(column[0],9) ^ gmul(column[3],13) ^ gmul(column[2],11);
				result[2] = gmul(column[2],14) ^ gmul(column[1],9) ^ gmul(column[0],13) ^ gmul(column[3],11);
				result[3] = gmul(column[3],14) ^ gmul(column[2],9) ^ gmul(column[1],13) ^ gmul(column[0],11);
					
				return result;
			}

			void Reference::InvMixColumns() {
				for( unsigned int col = 0; col < 4; col++ ){
					DataArray column( 4 );
					column[0] = mState[col * 4 + 0];
					column[1] = mState[col * 4 + 1];
					column[2] = mState[col * 4 + 2];
					column[3] = mState[col * 4 + 3];
					
					const DataArray result = InvMixColumn( column );
					
					mState[col * 4 + 0] = result[0];
					mState[col * 4 + 1] = result[1];
					mState[col * 4 + 2] = result[2];
					mState[col * 4 + 3] = result[3];
				}
			}
		}
	}
}
