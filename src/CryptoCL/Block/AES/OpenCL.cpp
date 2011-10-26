#include "CryptoCL/Block/AES/OpenCL.h"

#include <cmath>
#include <fstream>
#include <iostream>

#include <TQD/Compute/OpenCL/Queue.h>
#include <TQD/Compute/OpenCL/Buffer.h>
#include <TQD/Compute/OpenCL/Kernel.h>
#include <TQD/Compute/OpenCL/Device.h>
#include <TQD/Compute/OpenCL/Program.h>
#include <TQD/Compute/OpenCL/Context.h>
#include <TQD/Compute/OpenCL/Platform.h>
#include <TQD/Compute/OpenCL/PlatformManager.h>

using namespace tqd::Compute::OpenCL;

namespace CryptoCL {
	namespace Block {
		namespace AES {
			const char* DeviceUnavailiable::what() const throw() {
				return "Selected OpenCL Device Unavailiable";
			}
			
			OpenCL::OpenCL( const EDevice device ) : mDevice( device ), mPlatformManager( new PlatformManager ) {
			
			}
			
			OpenCL::~OpenCL() {
			
			}
			
			void OpenCL::OnInitialise( const RoundKey& key ) {
				Platform mPlatform = mPlatformManager->PlatformInstance( 0 );
				
				cl_device_type devType = 0;
				switch( mDevice ){
					case CPU:
						devType = CL_DEVICE_TYPE_CPU;
						break;
					case GPU:
						devType = CL_DEVICE_TYPE_GPU;
						break;
				};
				
				cl_device_id device = 0;
				cl_int error = clGetDeviceIDs( mPlatform.Data(), devType, 1, &device, 0 );
				if( error != CL_SUCCESS ) throw DeviceUnavailiable();
								
				Device dev( device );
				
				mContext = new Context( dev );
				mQueue = new Queue( *mContext, device );
				
				std::ifstream t( "data/aes.cl" );
				std::string source( ( std::istreambuf_iterator<char> ( t ) ), std::istreambuf_iterator<char>() );
				
				if( source.empty() ) exit( EXIT_FAILURE );
				
				Program program( *mContext, device );
				if( program.SourceCode( source ) ) {
					program.Compile();
				} else {
					throw std::exception();
				}

				/* Load Kernel */
				mKernelE = new Kernel( program, "encrypt" );
				mKernelD = new Kernel( program, "decrypt" );
			}
						
			const DataArray OpenCL::Encrypt( const DataArray& data ) {
				DataArray result( data.size() );
				
				if( isInitialised() ){
					DataArray aData( data.begin(), data.end() ), rKey = mKey.Value();
					const unsigned int rCount = mKey.Rounds();
					
					Buffer RoundKey( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * rKey.size(), &rKey[0] );
					Buffer Input( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * aData.size(), &aData[0] );
					Buffer Result( *mContext, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * aData.size(), 0 );
					
					const unsigned int dataSize = aData.size();
					
					bool paramSuccess = mKernelE->Parameter( 0, RoundKey );
					paramSuccess |= mKernelE->Parameter( 1, Input );
					paramSuccess |= mKernelE->Parameter( 2, Result );
					paramSuccess |= mKernelE->Parameter( 3, sizeof( cl_int ), &rCount );
					
					if( !paramSuccess ) {
						std::cerr << "Parameters Invalid" << std::endl;
						throw std::exception();
					}
					
					const size_t local_ws = 1;
					const size_t global_ws = dataSize / 16;

					mQueue->RangeKernel( *mKernelE, global_ws, local_ws );
							
					mQueue->ReadBuffer( Result, sizeof( char ) * aData.size(), &result[0] );
				}
				
				return result;
			}
						
			const DataArray OpenCL::Decrypt( const DataArray& data ) {
				DataArray result( data.size() );
				
				if( isInitialised() ) {
					DataArray aData( data.begin(), data.end() ), rKey = mKey.Value();
					const unsigned int rCount = mKey.Rounds();
						
					Buffer RoundKey( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * rKey.size(), &rKey[0] );
					Buffer Input( *mContext, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * aData.size(), &aData[0] );
					Buffer Result( *mContext, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * aData.size(), 0 );
					
					const unsigned int dataSize = aData.size();
					
					bool paramSuccess = mKernelD->Parameter( 0, RoundKey );
					paramSuccess |= mKernelD->Parameter( 1, Input );
					paramSuccess |= mKernelD->Parameter( 2, Result );
					paramSuccess |= mKernelD->Parameter( 3, sizeof( cl_int ), &rCount );
					
					if( !paramSuccess ) {
						std::cerr << "Parameters Invalid" << std::endl;
						throw std::exception();
					}
					
					const size_t local_ws = 1;
					const size_t global_ws = dataSize / 16;

					mQueue->RangeKernel( *mKernelD, global_ws, local_ws );
							
					mQueue->ReadBuffer( Result, sizeof( char ) * aData.size(), &result[0] );
				}
				
				return result;
			}
		}
	}
}
