#include "CryptoCL/Block/AES/Reference.h"

#include <iomanip>
#include <iostream>

namespace CryptoCL {
	namespace Block {
		namespace AES {
			/* Public Functions */
			Reference::Reference( const Mode::BlockMode mode, const DataArray& iv ) 
				: AESBlockCipher( mode, iv ) {
			
			}
			
			const DataArray Reference::Encrypt( const DataArray& data ) {
				const std::vector<DataArray> blocks = SplitArray( data, 16 );
				std::vector<DataArray> blockResults( blocks.size() );
				
				for( unsigned int i = 0; i < blocks.size(); i++ ){
					blockResults[i] = blocks[i];
					
					if( mMode == Mode::CipherBlockChaining ){
						if( i == 0 ){
							blockResults[i] = XORBlock( blockResults[i], mInitialisationVector );
						}else{
							blockResults[i] = XORBlock( blockResults[i], blockResults[i-1] );
						}
					}
					
					blockResults[i] = Encrypt( blockResults[i], mKey );
				}
				
				DataArray result;
				for( unsigned int i = 0; i < blockResults.size(); i++ ){
					result.insert( result.end(), blockResults[i].begin(), blockResults[i].end() );
				}
								
				return result;
			}
			
			const DataArray Reference::Decrypt( const DataArray& data ) {
				const std::vector<DataArray> blocks = SplitArray( data, 16 );
				std::vector<DataArray> blockResults( blocks.size() );
				
				for( unsigned int i = 0; i < blocks.size(); i++ ){
					blockResults[i] = Decrypt( blocks[i], mKey );
					
					if( mMode == Mode::CipherBlockChaining ){
						if( i == 0 ){
							blockResults[i] = XORBlock( blockResults[i], mInitialisationVector );
						}else{
							blockResults[i] = XORBlock( blockResults[i], blocks[i-1] );
						}
					}					
				}
				
				DataArray result;
				for( unsigned int i = 0; i < blockResults.size(); i++ ){
					result.insert( result.end(), blockResults[i].begin(), blockResults[i].end() );
				}
								
				return result;
			}
			
			const DataArray Reference::Encrypt( const DataArray& block, const RoundKey& rkey ) const {
				DataArray result( block );
				
				result = AddRoundKey( result, rkey, 0 );
				
				for( unsigned int j = 1; j < mKey.Rounds(); j++ ){
					result = AddRoundKey( MixColumns( ShiftRows( SubBytes( result ) ) ), rkey, j );
				}
				
				result = AddRoundKey( ShiftRows( SubBytes( result ) ), rkey, rkey.Rounds() );
				
				return result;
			}
			
			const DataArray Reference::Decrypt( const DataArray& block, const RoundKey& rkey ) const {
				DataArray result( block );
				
				result = AddRoundKey( result, rkey, rkey.Rounds() );
				
				for( unsigned int j = mKey.Rounds() - 1; j > 0; j-- ){
					result = InvMixColumns( AddRoundKey( InvSubBytes( InvShiftRows( result ) ), rkey, j ) );
				}
			
				result = AddRoundKey(  InvShiftRows( InvSubBytes( result ) ), rkey, 0 );
				
				return result;
			}
			
			/* General Helper Functions */
			const unsigned char gmul( const unsigned char a, const unsigned char b ) {
				unsigned char p = 0, aBit = a, bBit = b, hi_bit_set = 0;
				for(unsigned char counter = 0; counter < 8; counter++) {
					if((bBit & 1) == 1) p ^= aBit;
					hi_bit_set = (aBit & 0x80);
					aBit <<= 1;
					if(hi_bit_set == 0x80) aBit ^= 0x1b;		
					bBit >>= 1;
				}
				return p;
			}
			
			/* Protected Functions */
			const DataArray Reference::XORBlock( const DataArray& a, const DataArray& b ) const {
				DataArray result( a.size() );
				
				for( unsigned int i = 0; i < a.size(); i++ ){
					result[i] = a[i] ^ b[i];
				}
				
				return result;
			}
			
			const DataArray Reference::AddRoundKey( const DataArray& block, const RoundKey& key, const unsigned int round ) const {
				return XORBlock( block, key.Value( round ) );
			}
					
			/* Encryption Helpers */
			const DataArray Reference::SubBytes( const DataArray& block ) const {
				DataArray result( block.size() );
				
				for( unsigned int i = 0; i < block.size(); i++ ){
					result[i] = SBox[block[i]];
				}
				
				return result;
			}
			
			const DataArray Reference::ShiftRows( const DataArray& block ) const {
				DataArray result( block.size() );
				const DataArray TempState( block.begin(), block.end() );
				
				for (unsigned int i = 0; i < 16; i++) {
					unsigned int row = i % 4;
					unsigned int k = (i + (row * 4)) % 16;
					result[i] = TempState[k];
				}
				
				return result;
			}

			void OptimizedMixColumn( DataArray& column, const unsigned int pos ) {
				const unsigned char cZero = gmul(column[pos+0],2), cOne = gmul(column[pos+1],2), cTwo = gmul(column[pos+2],2), cThree = gmul(column[pos+3],2);
				
				const unsigned char a = cZero  ^ column[pos+3] ^ column[pos+2] ^ cOne   ^ column[pos+1];
				const unsigned char b = cOne   ^ column[pos+0] ^ column[pos+3] ^ cTwo   ^ column[pos+2];
				const unsigned char c = cTwo   ^ column[pos+1] ^ column[pos+0] ^ cThree ^ column[pos+3];
				const unsigned char d = cThree ^ column[pos+2] ^ column[pos+1] ^ cZero  ^ column[pos+0];
				
				column[pos+0] = a; column[pos+1] = b; column[pos+2] = c; column[pos+3] = d;
			}

			const DataArray Reference::MixColumns( const DataArray& block ) const {
				DataArray result( block );
				
				OptimizedMixColumn( result, 0 );
				OptimizedMixColumn( result, 4 );
				OptimizedMixColumn( result, 8 );
				OptimizedMixColumn( result, 12 );
				
				return result;
			}
			
			/* Decryption Helpers */
			const DataArray Reference::InvSubBytes( const DataArray& block ) const {
				DataArray result( block.size() );
				for( unsigned int i = 0; i < block.size(); i++ ){
					result[i] = InvSBox[block[i]];
				}
				return result;
			}
			
			const DataArray Reference::InvShiftRows( const DataArray& block ) const {
				DataArray result( block.size() );
				
				const DataArray TempState( block );
				for (unsigned int i = 0; i < 16; i++) {
					unsigned int row = i % 4;
					unsigned int k = (i - (row * 4)) % 16;
					result[i] = TempState[k];
				}
				
				return result;
			}
			
			void InvMixColumn( DataArray& column, const unsigned int pos ){
				const unsigned char a = gmul(column[pos+0],14) ^ gmul(column[pos+3],9) ^ gmul(column[pos+2],13) ^ gmul(column[pos+1],11);
				const unsigned char b = gmul(column[pos+1],14) ^ gmul(column[pos+0],9) ^ gmul(column[pos+3],13) ^ gmul(column[pos+2],11);
				const unsigned char c = gmul(column[pos+2],14) ^ gmul(column[pos+1],9) ^ gmul(column[pos+0],13) ^ gmul(column[pos+3],11);
				const unsigned char d = gmul(column[pos+3],14) ^ gmul(column[pos+2],9) ^ gmul(column[pos+1],13) ^ gmul(column[pos+0],11);
					
				column[pos+0] = a; column[pos+1] = b; column[pos+2] = c; column[pos+3] = d;
			}

			const DataArray Reference::InvMixColumns( const DataArray& block ) const {
				DataArray result( block );
				
				InvMixColumn( result, 0 );
				InvMixColumn( result, 4 );
				InvMixColumn( result, 8 );
				InvMixColumn( result, 12 );
				
				return result;
			}
		}
	}
}
