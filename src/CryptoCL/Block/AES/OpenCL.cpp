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
			
			OpenCL::OpenCL( const EDevice device, const Mode::BlockMode mode, const DataArray& iv ) 
				: AESBlockCipher( mode, iv ), mDevice( device ), mPlatformList( new PlatformList ) {
			
			}
			
			OpenCL::~OpenCL() {
				delete mPlatformList;
				
				if( mEncryption ) delete mEncryption;
				if( mDecryption ) delete mDecryption;
				if( mDecryptionCBC ) delete mDecryptionCBC;
				
				if( mQueue ) delete mQueue;
				if( mContext ) delete mContext;
			}
			
			void OpenCL::OnInitialise( const RoundKey& key ) {
				cl_device_type devType = 0;
				switch( mDevice ){
					case CPU:
						devType = CL_DEVICE_TYPE_CPU;
						break;
					case GPU:
						devType = CL_DEVICE_TYPE_GPU;
						break;
				};
				
				Device device;
				
				const unsigned int platforms = mPlatformList->Count();
				for( unsigned int i = 0; i < platforms; i++ ){
					DeviceList devList( mPlatformList->GetPlatform( i ) );
					
					const unsigned int devices = devList.Count();
					for( unsigned int j = 0; j < devices; j++ ){
						Device temp = devList.GetDevice( j );
						
						cl_device_type type;
						temp.InfoData( CL_DEVICE_TYPE, &type );
						
						if( type == devType ) {
							device = temp;
							break;
						}
					}
				}
				
				if( !device.isValid() ) throw DeviceUnavailiable();
								
				mContext = new Context( device );
				mQueue = new Queue( *mContext, device );
				
				// Encryption 
				std::ifstream eFile( "data/aes_encrypt.cl" );
				std::string eSource( ( std::istreambuf_iterator<char> ( eFile ) ), std::istreambuf_iterator<char>() );
				
				if( eSource.empty() ) exit( EXIT_FAILURE );
				
				mEncryption = new Program( *mContext, device, eSource );
				
				// Decryption 
				std::ifstream dFile( "data/aes_decrypt.cl" );
				std::string dSource( ( std::istreambuf_iterator<char> ( dFile ) ), std::istreambuf_iterator<char>() );
				
				if( dSource.empty() ) exit( EXIT_FAILURE );
				
				mDecryption = new Program( *mContext, device, dSource );
				
				// Decryption 
				std::ifstream dFileCBC( "data/aes_decryptCBC.cl" );
				std::string dSourceCBC( ( std::istreambuf_iterator<char> ( dFileCBC ) ), std::istreambuf_iterator<char>() );
				
				if( dSourceCBC.empty() ) exit( EXIT_FAILURE );
				
				mDecryptionCBC = new Program( *mContext, device, dSourceCBC );
			}
						
			const DataArray OpenCL::Encrypt( const DataArray& data ) {
				DataArray result;
				
				if( isInitialised() ){
					DataArray roundKey( mKey.Value() );
					const unsigned int roundCount = mKey.Rounds();
					
					Buffer RoundKey( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * roundKey.size(), &roundKey[0] );
					
					Kernel kernel = mEncryption->GetKernel("encrypt");
					
					if( mMode != Mode::CipherBlockChaining ){
						DataArray aData( data.begin(), data.end() );
						
						Buffer Input( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * aData.size(), &aData[0] );
						Buffer Result( *mContext, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * aData.size(), 0 );
						
						bool paramSuccess = kernel.Parameter( 0, RoundKey );
						paramSuccess |= kernel.Parameter( 1, Input );
						paramSuccess |= kernel.Parameter( 2, Result );
						paramSuccess |= kernel.Parameter( 3, sizeof( cl_int ), &roundCount );
						
						if( !paramSuccess ) {
							std::cerr << "Parameters Invalid" << std::endl;
							throw std::exception();
						}

						mQueue->RangeKernel( kernel, 1, aData.size() / 16 );
						
						result.resize( aData.size() );
						mQueue->ReadBuffer( Result, sizeof( unsigned char ) * aData.size(), &result[0] );
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
							
							
							Buffer Input( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * inData.size(), &inData[0] );
							Buffer Result( *mContext, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * inData.size(), 0 );
							
							bool paramSuccess = kernel.Parameter( 0, RoundKey );
							paramSuccess |= kernel.Parameter( 1, Input );
							paramSuccess |= kernel.Parameter( 2, Result );
							paramSuccess |= kernel.Parameter( 3, sizeof( cl_int ), &roundCount );
							
							if( !paramSuccess ) {
								std::cerr << "Parameters Invalid" << std::endl;
								throw std::exception();
							}
							
							mQueue->RangeKernel( kernel, 1, 1 );
							
							DataArray outData( inData.size() );
							mQueue->ReadBuffer( Result, sizeof( unsigned char ) * outData.size(), &outData[0] );
							
							result.insert( result.end(), outData.begin(), outData.end() );
						}
					}
				}
				
				return result;
			}
						
			const DataArray OpenCL::Decrypt( const DataArray& data ) {
				DataArray result( data.size() );
				
				if( isInitialised() ) {
					DataArray inData( data ), roundKey( mKey.Value() );
					const unsigned int rCount = mKey.Rounds();
					
					const size_t local_ws = 1, global_ws = inData.size() / 16;
					
					Buffer RoundKey( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * roundKey.size(), &roundKey[0] );
					Buffer Input( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * inData.size(), &inData[0] );
					Buffer Result( *mContext, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * inData.size(), 0 );
					
					if( mMode != Mode::CipherBlockChaining ){
						Kernel kernel = mDecryption->GetKernel( "decrypt" );
						
						bool paramSuccess = kernel.Parameter( 0, RoundKey );
						paramSuccess |= kernel.Parameter( 1, Input );
						paramSuccess |= kernel.Parameter( 2, Result );
						paramSuccess |= kernel.Parameter( 3, sizeof( cl_int ), &rCount );
						
						if( !paramSuccess ) {
							std::cerr << "Parameters Invalid" << std::endl;
							throw std::exception();
						}

						mQueue->RangeKernel( kernel, global_ws, local_ws );
					}else{
						Kernel kernel = mDecryptionCBC->GetKernel( "decryptCBC" );
						
						DataArray previous;
						previous.insert( previous.end(), mInitialisationVector.begin(), mInitialisationVector.end() );
						previous.insert( previous.end(), inData.begin(), inData.end() - 16 );
					
						Buffer Previous( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * previous.size(), &previous[0] );
						
						bool paramSuccess = kernel.Parameter( 0, RoundKey );
						paramSuccess |= kernel.Parameter( 1, Input );
						paramSuccess |= kernel.Parameter( 2, Previous );
						paramSuccess |= kernel.Parameter( 3, Result );
						paramSuccess |= kernel.Parameter( 4, sizeof( cl_int ), &rCount );
						
						if( !paramSuccess ) {
							std::cerr << "Parameters Invalid" << std::endl;
							throw std::exception();
						}

						mQueue->RangeKernel( kernel, global_ws, local_ws );
					}
					
					mQueue->ReadBuffer( Result, sizeof( char ) * inData.size(), &result[0] );
				}
				
				return result;
			}
		}
	}
}
