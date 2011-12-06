#include "CryptoCL/Block/AES/OpenCL.h"

#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>

#include <TQD/Compute/OpenCL/Queue.h>
#include <TQD/Compute/OpenCL/Buffer.h>
#include <TQD/Compute/OpenCL/Kernel.h>
#include <TQD/Compute/OpenCL/Device.h>
#include <TQD/Compute/OpenCL/Program.h>
#include <TQD/Compute/OpenCL/Context.h>
#include <TQD/Compute/OpenCL/Platform.h>
#include <TQD/Compute/OpenCL/DeviceList.h>
#include <TQD/Compute/OpenCL/PlatformList.h>

using namespace tqd::Compute::OpenCL;

namespace CryptoCL {
	namespace Block {
		namespace AES {
			const char* DeviceUnavailiable::what() const throw() {
				return "Selected OpenCL Device Unavailiable";
			}
			
			OpenCL::OpenCL( const EDevice deviceType, const Mode::BlockMode mode ) 
				: AESBlockCipher( mode ), mQueue( 0 ), mContext( 0 ) {
				
				cl_device_type devType = 0;
				switch( deviceType ){
					case CPU:
						devType = CL_DEVICE_TYPE_CPU;
						break;
					case GPU:
						devType = CL_DEVICE_TYPE_GPU;
						break;
				};
				
				Device device;
				
				PlatformList platformList;
				
				const unsigned int platforms = platformList.Count();
				for( unsigned int i = 0; i < platforms; i++ ){
					DeviceList devList( platformList.GetPlatform( i ) );
					
					//std::cout << "Platform: " << platformList.GetPlatform( i ).Name() << std::endl;
					
					const unsigned int devices = devList.Count();
					for( unsigned int j = 0; j < devices; j++ ){
						Device temp = devList.GetDevice( j );
						
						//std::cout << "\tDevice: " << temp.InfoString( CL_DEVICE_NAME ) << std::endl;
						
						cl_device_type type;
						temp.InfoData( CL_DEVICE_TYPE, &type );
						
						if( type == devType ) {
							//std::cout << "\t\tSelected" << std::endl;
							device = temp;
							break;
						}else{
							//std::cout << "\t\tIgnored" << std::endl;
						}
					}
				}
				
				Setup( device );
				
			}
			
			OpenCL::OpenCL( Device& device, const Mode::BlockMode mode ) 
				: AESBlockCipher( mode ), mQueue( 0 ), mContext( 0 ) {
			
				Setup( device );
			}
			
			OpenCL::OpenCL( const OpenCL& other ) 
				: AESBlockCipher( other.mMode ),
				mQueue( other.mQueue ), mContext( other.mContext ), 
				mEncryption( other.mEncryption ), mDecryption( other.mDecryption ) {
			
			}
			
			OpenCL& OpenCL::operator=( const OpenCL& other ) {
				if( this != &other ){
					// Block Cipher
					mMode = other.mMode;
					
					// OpenCL
					mQueue = other.mQueue;
					mContext = other.mContext;
					mEncryption = other.mEncryption;
					mDecryption = other.mDecryption;
				}
				
				return *this;
			}
			
			OpenCL::~OpenCL() {
				if( mQueue ) delete mQueue;
				if( mContext ) delete mContext;
			}
			
			void OpenCL::Setup( tqd::Compute::OpenCL::Device& device ) {
				if( !device.isValid() ) throw DeviceUnavailiable();
				
				mContext = new Context( device );
				mQueue = new Queue( *mContext, device );
				
				mEncryption = CreateProgramFromFile( *mContext, device, "data/block/aes/encrypt.cl" );
				if( !mEncryption.isValid() ) exit( EXIT_FAILURE );
				
				mDecryption = CreateProgramFromFile( *mContext, device, "data/block/aes/decrypt.cl" );
				if( !mDecryption.isValid() ) exit( EXIT_FAILURE );
				
				mCBC = CreateProgramFromFile( *mContext, device, "data/block/cbc.cl" );
				if( !mCBC.isValid() ) exit( EXIT_FAILURE );
			}
						
			const DataArray OpenCL::Encrypt( const DataArray& data, const CryptoCL::Key& key, const DataArray& iv ) const {
				DataArray result( data.size() );
				
				Event read;
				
				if( mMode == Mode::ElectronicCookBook ){
					read = EncryptChunk( data, result, key );
				}else{
					read = EncryptChunkCBC( data, result, key, iv );
				}
				
				read.Wait();
				
				return result;
			}
			
			const ArrayVector OpenCL::Encrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv ) const {
				ArrayVector result( data.size() );
				
				EventList list;
				for( unsigned int i = 0; i < data.size(); i++ ){
					result[i].resize( data[i].size() );
					
					Event cipher;
					if( mMode == Mode::ElectronicCookBook ){
						cipher = EncryptChunk( data[i], result[i], *key[i] );
					}else{
						cipher = EncryptChunkCBC( data[i], result[i], *key[i], iv[i] );
					}
					list.push_back( cipher );
				}
				Wait( list );
				
				return result;
			}
			
			const Event OpenCL::EncryptChunk( const DataArray& data, DataArray& result, const CryptoCL::Key& key, const DataArray& iv ) const {
				const RoundKey& rkey = dynamic_cast<const RoundKey&>(key);
				const unsigned int Rounds = rkey.Rounds(), Blocks = data.size() / 16;
					
				ReadOnlyBuffer RoundKey( *mContext, rkey.Value() );
				ReadOnlyBuffer Input( *mContext, data );
				ReadWriteBuffer Result( *mContext, data.size() );
				
				EventList list;
				for( unsigned int i = 0; i < Blocks; i++ ){
					Event block = EncryptBlock( RoundKey, Input, Result, Rounds, i );
					list.push_back( block );
				}
				
				return mQueue->ReadBuffer( Result, sizeof( char ) * data.size(), &result[0], list );
			}
			
			const Event OpenCL::EncryptChunkCBC( const DataArray& data, DataArray& result, const CryptoCL::Key& key, const DataArray& iv ) const {
				const RoundKey& rkey = dynamic_cast<const RoundKey&>(key);
				const unsigned int Rounds = rkey.Rounds(), Blocks = data.size() / 16;
					
				ReadOnlyBuffer RoundKey( *mContext, rkey.Value() );
				ReadOnlyBuffer Input( *mContext, data );
				ReadWriteBuffer Result( *mContext, data.size() );
				
				DataArray previous( iv );
				previous.resize( data.size() );
				ReadOnlyBuffer Previous( *mContext, previous );
				
				Event block = EncryptBlock( RoundKey, Input, Result, Rounds, 0, XORBlock( Input, 0, Previous, 0, Event() ) );
				for( unsigned int i = 1; i < Blocks; i++ ){
					block = EncryptBlock( RoundKey, Input, Result, Rounds, i, XORBlock( Input, i, Result, i-1, block ) );
				}
				
				return mQueue->ReadBuffer( Result, sizeof( char ) * data.size(), &result[0], block );
			}
			
			const Event OpenCL::EncryptBlock( const Buffer& key, const Buffer& input, const Buffer& result, unsigned int rounds, unsigned int block, const Event& event ) const {
				Kernel kernel = mEncryption.GetKernel( "encrypt" );
				
				kernel.Parameter( 0, key );
				kernel.Parameter( 1, sizeof(cl_int), &rounds );
				kernel.Parameter( 2, input );
				kernel.Parameter( 3, result );
				kernel.Parameter( 4, sizeof( cl_int ), &block );
				
				EventList list;
				if( event.isValid() ){
					list.push_back( event );
				}
				
				return mQueue->RangeKernel( kernel, 1, list );
			}
			
			const DataArray OpenCL::Decrypt( const DataArray& data, const CryptoCL::Key& key, const DataArray& iv ) const {
				DataArray result( data.size() );
				
				Event read;
				
				if( mMode == Mode::ElectronicCookBook ){
					read = DecryptChunk( data, result, key );
				}else{
					read = DecryptChunkCBC( data, result, key, iv );
				}
				
				read.Wait();
									
				return result;
			}
			
			const ArrayVector OpenCL::Decrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv ) const {
				ArrayVector result( data.size() );
				
				EventList list;
				for( unsigned int i = 0; i < data.size(); i++ ){
					result[i].resize( data[i].size() );
					
					Event cipher;
					if( mMode == Mode::ElectronicCookBook ){
						cipher = DecryptChunk( data[i], result[i], *key[i] );
					}else{
						cipher = DecryptChunkCBC( data[i], result[i], *key[i], iv[i] );
					}
					list.push_back( cipher );
				}
				Wait( list );
				
				return result;
			}
			
			const Event OpenCL::DecryptChunk( const DataArray& data, DataArray& result, const CryptoCL::Key& key ) const {
				const RoundKey& rkey = dynamic_cast<const RoundKey&>(key);
				const unsigned int Rounds = rkey.Rounds(), Blocks = data.size() / 16;
					
				ReadOnlyBuffer RoundKey( *mContext, rkey.Value() );
				ReadOnlyBuffer Input( *mContext, data );
				ReadWriteBuffer Result( *mContext, data.size() );
								
				EventList list;
				for( unsigned int i = 0; i < Blocks; i++ ){
					list.push_back( DecryptBlock( RoundKey, Input, Result, Rounds, i ) );
				}
				
				return mQueue->ReadBuffer( Result, sizeof( char ) * data.size(), &result[0], list );
			}
			
			const Event OpenCL::DecryptChunkCBC( const DataArray& data, DataArray& result, const CryptoCL::Key& key, const DataArray& iv ) const {
				const RoundKey& rkey = dynamic_cast<const RoundKey&>(key);
				const unsigned int Rounds = rkey.Rounds(), Blocks = data.size() / 16;
					
				ReadOnlyBuffer RoundKey( *mContext, rkey.Value() );
				ReadOnlyBuffer Input( *mContext, data );
				ReadWriteBuffer Result( *mContext, data.size() );
				
				DataArray previous;
				previous.insert( previous.end(), iv.begin(), iv.end() );
				previous.insert( previous.end(), data.begin(), data.end() - 16 );
				
				ReadOnlyBuffer Previous( *mContext, previous );
								
				EventList list;
				for( unsigned int i = 0; i < Blocks; i++ ){
					list.push_back( XORBlock( Result, i, Previous, i, DecryptBlock( RoundKey, Input, Result, Rounds, i ) ) );
				}
				
				return mQueue->ReadBuffer( Result, sizeof( char ) * data.size(), &result[0], list );
			}
			
			const Event OpenCL::DecryptBlock( const Buffer& key, const Buffer& input, const Buffer& result, unsigned int rounds, unsigned int block ) const {
				Kernel kernel = mDecryption.GetKernel( "decrypt" );
				
				kernel.Parameter( 0, key );
				kernel.Parameter( 1, sizeof(cl_int), &rounds );
				kernel.Parameter( 2, input );
				kernel.Parameter( 3, result );
				kernel.Parameter( 4, sizeof( cl_int ), &block );
				
				return mQueue->RangeKernel( kernel, 1 );
			}
			
			const Event OpenCL::XORBlock( const Buffer& block, const size_t blockOffset, const Buffer& value, const size_t valOffset, const Event& event ) const {
				Kernel kernel = mCBC.GetKernel( "CipherBlockChain" );
				
				kernel.Parameter( 0, block );
				kernel.Parameter( 1, sizeof( cl_int ), &blockOffset );
				kernel.Parameter( 2, value );
				kernel.Parameter( 3, sizeof( cl_int ), &valOffset );
				
				Event retVal;
				if( !event.isValid() ){
					retVal = mQueue->RangeKernel( kernel, 1 );
				}else{
					retVal = mQueue->RangeKernel( kernel, 1, event );
				}
			
				return retVal;
			}
		}
	}
}
