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
			
			OpenCL::OpenCL( const EDevice deviceType, const Mode::BlockMode mode, const DataArray& iv ) 
				: AESBlockCipher( mode, iv ), mQueue( 0 ), mContext( 0 ) {
				
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
			
			OpenCL::OpenCL( Device& device, const Mode::BlockMode mode, const DataArray& iv ) 
				: AESBlockCipher( mode, iv ), mQueue( 0 ), mContext( 0 ) {
			
				Setup( device );
			}
			
			OpenCL::OpenCL( const OpenCL& other ) 
				: AESBlockCipher( other.mMode, other.mInitialisationVector ),
				mQueue( other.mQueue ), mContext( other.mContext ), 
				mEncryption( other.mEncryption ), mDecryption( other.mDecryption ) {
			
			}
			
			OpenCL& OpenCL::operator=( const OpenCL& other ) {
				if( this != &other ){
					// Block Cipher
					mMode = other.mMode;
					mInitialised = other.mInitialised;
					mInitialisationVector = other.mInitialisationVector;
					
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
			
			void OpenCL::OnInitialise( const RoundKey& key ) {
				
			}
			
			void OpenCL::Setup( tqd::Compute::OpenCL::Device& device ) {
				if( !device.isValid() ) throw DeviceUnavailiable();
				
				mContext = new Context( device );
				mQueue = new Queue( *mContext, device );
				
				// Encryption ECB
				mEncryption[Mode::ElectronicCookBook] = CreateProgramFromFile( *mContext, device, "data/block/ecb/aes/encrypt.cl" );
				if( !mEncryption[Mode::ElectronicCookBook].isValid() ) exit( EXIT_FAILURE );
				
				// Decryption ECB
				mDecryption[Mode::ElectronicCookBook] = CreateProgramFromFile( *mContext, device, "data/block/ecb/aes/decrypt.cl" );
				if( !mDecryption[Mode::ElectronicCookBook].isValid() ) exit( EXIT_FAILURE );
				
				// Encryption CBC
				mEncryption[Mode::CipherBlockChaining] = CreateProgramFromFile( *mContext, device, "data/block/cbc/aes/encrypt.cl" );
				if( !mEncryption[Mode::CipherBlockChaining].isValid() ) exit( EXIT_FAILURE );
				
				// Decryption CBC
				mDecryption[Mode::CipherBlockChaining] = CreateProgramFromFile( *mContext, device, "data/block/cbc/aes/decrypt.cl" );
				if( !mDecryption[Mode::CipherBlockChaining].isValid() ) exit( EXIT_FAILURE );
			}
						
			const DataArray OpenCL::Encrypt( const DataArray& data ) {
				DataArray result( data.size() );
				
				if( isInitialised() ){
					const unsigned int Rounds = mKey.Rounds();
					DataArray inData( data ), roundKey( mKey.Value() );
					const size_t blockCount = data.size() / 16;
					
					ReadOnlyBuffer RoundKey( *mContext, sizeof( unsigned char ) * roundKey.size(), &roundKey[0] );				
					
					Kernel kernel = mEncryption[mMode].GetKernel( "encrypt" );
										
					if( mMode != Mode::CipherBlockChaining ){
						WriteOnlyBuffer Result( *mContext, sizeof( unsigned char ) * inData.size() );
						ReadOnlyBuffer Input( *mContext, sizeof( unsigned char ) * inData.size(), &inData[0] );
						
						bool paramSuccess = kernel.Parameter( 0, RoundKey );
						paramSuccess |= kernel.Parameter( 1, sizeof( cl_uint ), &Rounds );
						paramSuccess |= kernel.Parameter( 2, Input );
						paramSuccess |= kernel.Parameter( 3, Result );
						paramSuccess |= kernel.Parameter( 4, sizeof( cl_uint ), &blockCount );
						
						if( !paramSuccess ) {
							std::cerr << "Parameters Invalid" << std::endl;
							throw std::exception();
						}

						mQueue->RangeKernel( kernel, ( blockCount % 2 == 0 ) ? blockCount : ( blockCount + 1 ) );
				
						mQueue->ReadBuffer( Result, sizeof( char ) * inData.size(), &result[0] );
					}else{
						const unsigned int blocks = data.size() / 16;
						
						for( unsigned int i = 0; i < blocks; i++ ){
							const unsigned int sPos = i * 16;
							
							DataArray inData( data.begin() + sPos, data.begin() + sPos + 16 );
							
							if( mMode == Mode::CipherBlockChaining ) {
									if( i == 0 ) {
											for(unsigned int s = 0; s < 16; s++ ) inData[s] ^= mInitialisationVector[s];
									}else{
											for(unsigned int s = 0; s < 16; s++ ) inData[s] ^= result[sPos-16+s];
									}
							}
							
							
							ReadOnlyBuffer Input( *mContext, sizeof( unsigned char ) * inData.size(), &inData[0] );
							WriteOnlyBuffer Result( *mContext, sizeof( unsigned char ) * inData.size() );
							
							bool paramSuccess = kernel.Parameter( 0, RoundKey );
							paramSuccess |= kernel.Parameter( 1, sizeof( cl_uint ), &Rounds );
							paramSuccess |= kernel.Parameter( 2, Input );
							paramSuccess |= kernel.Parameter( 3, Result );
							
							int blockCount = 1;
							paramSuccess |= kernel.Parameter( 4, sizeof( cl_int ), &blockCount );
							
							if( !paramSuccess ) {
								std::cerr << "Parameters Invalid" << std::endl;
								throw std::exception();
							}
							
							mQueue->RangeKernel( kernel, 1, 1 );
							
							DataArray outData( inData.size() );
							mQueue->ReadBuffer( Result, sizeof( unsigned char ) * outData.size(), &outData[0] );
							
							for( unsigned int i = 0; i < 16; i++ ){
								result[sPos+i] = outData[i];
							}
						}
					}
				}
				
				return result;
			}
						
			const DataArray OpenCL::Decrypt( const DataArray& data ) {
				DataArray result( data.size() );
				
				if( isInitialised() ) {
					const unsigned int Rounds = mKey.Rounds(), Blocks = data.size() / 16;
					
					ReadOnlyBuffer RoundKey( *mContext, mKey.Value() );
					ReadOnlyBuffer Input( *mContext, data );
					WriteOnlyBuffer Result( *mContext, data.size() );
					
					ReadOnlyBuffer *Previous = 0;
					if( mMode == Mode::CipherBlockChaining ){
						DataArray previous;
						previous.insert( previous.end(), mInitialisationVector.begin(), mInitialisationVector.end() );
						previous.insert( previous.end(), data.begin(), data.end() - 16 );
					
						Previous = new ReadOnlyBuffer( *mContext, previous );
					}
					
					Kernel kernel = mDecryption[mMode].GetKernel("decrypt");
						
					int param = 0;
					kernel.Parameter( param++, RoundKey );
					kernel.Parameter( param++, sizeof( cl_uint ), &Rounds );
					kernel.Parameter( param++, Input );
					if( mMode == Mode::CipherBlockChaining ) kernel.Parameter( param++, *Previous );
					kernel.Parameter( param++, Result );
					kernel.Parameter( param++, sizeof( cl_uint ), &Blocks );
						
					Event cipher = mQueue->RangeKernel( kernel, ( Blocks % 2 == 0 ) ? Blocks : ( Blocks + 1 ) );
					
					mQueue->ReadBuffer( Result, sizeof( char ) * data.size(), &result[0] );
					
					if( mMode == Mode::CipherBlockChaining ) delete Previous;
				}
				
				return result;
			}
		}
	}
}
