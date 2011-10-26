#include "CryptoCL/AES/OpenCL.h"

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
	namespace AES {
		OpenCL::OpenCL( const RoundKey& key ) : mKey( key ), mPlatformManager( new PlatformManager ){
			InitialiseCPU();
			InitialiseGPU();
		}
		
		OpenCL::~OpenCL() {
		
		}
	
		void OpenCL::InitialiseCPU() {
			Platform mPlatform = mPlatformManager->PlatformInstance( 0 );
			
			cl_device_id cpudevice = 0;
			cl_int error = clGetDeviceIDs( mPlatform.Data(), CL_DEVICE_TYPE_CPU, 1, &cpudevice, 0 );
			if( error != CL_SUCCESS ){
				mCPU = false;
				cpudevice = 0;
			}else{
				mCPU = true;
				Device cpu( cpudevice );
				
				mContextCPU = new Context( cpu );
				mQueueCPU = new Queue( *mContextCPU, cpudevice );
				
				std::ifstream t( "data/aes.cl" );
				std::string source( ( std::istreambuf_iterator<char> ( t ) ), std::istreambuf_iterator<char>() );
				
				if( source.empty() ) exit( EXIT_FAILURE );
				
				Program program( *mContextCPU, cpudevice );
				if( program.SourceCode( source ) ) {
					program.Compile();
				} else {
					throw std::exception();
				}

				/* Load Kernel */
				mEKernelCPU = new Kernel( program, "encrypt" );
				mDKernelCPU = new Kernel( program, "decrypt" );

			}
		}
		
		void OpenCL::InitialiseGPU() {
			Platform mPlatform = mPlatformManager->PlatformInstance( 0 );
			
			cl_device_id gpudevice = 0;
			cl_int error = clGetDeviceIDs( mPlatform.Data(), CL_DEVICE_TYPE_GPU, 1, &gpudevice, 0 );
			if( error != CL_SUCCESS ){
				mGPU = false;
				gpudevice = 0;
			}else{
				mGPU = true;
				Device gpu( gpudevice );
				
				mContextGPU = new Context( gpu );
				mQueueGPU = new Queue( *mContextGPU, gpudevice );
				
				std::ifstream t( "data/aes.cl" );
				std::string source( ( std::istreambuf_iterator<char> ( t ) ), std::istreambuf_iterator<char>() );
				
				if( source.empty() ) exit( EXIT_FAILURE );
				
				Program program( *mContextGPU, gpudevice );
				if( program.SourceCode( source ) ) {
					program.Compile();
				} else {
					throw std::exception();
				}

				/* Load Kernel */
				mEKernelGPU = new Kernel( program, "encrypt" );
				mDKernelGPU = new Kernel( program, "decrypt" );
			}	
		}
		
		bool OpenCL::isCPUAvailiable() const {
			return mCPU;
		}
		
		bool OpenCL::isGPUAvailiable() const{
			return mGPU;
		}
		
		const DataArray OpenCL::CPUEncrypt( const DataArray& data ) {
			DataArray aData( data.begin(), data.end() ), rKey = mKey.Value();
			
			Buffer RoundKey( *mContextCPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * rKey.size(), &rKey[0] );
			Buffer Input( *mContextCPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * aData.size(), &aData[0] );
			Buffer Result( *mContextCPU, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * aData.size(), 0 );
			
			const unsigned int dataSize = aData.size();
			
			bool paramSuccess = mEKernelCPU->Parameter( 0, RoundKey );
			paramSuccess |= mEKernelCPU->Parameter( 1, Input );
			paramSuccess |= mEKernelCPU->Parameter( 2, Result );
			
			if( !paramSuccess ) {
				std::cerr << "Parameters Invalid" << std::endl;
				throw std::exception();
			}
			
			const size_t local_ws = 1;
			const size_t global_ws = dataSize / 16;

			DataArray result( dataSize );
			mQueueCPU->RangeKernel( *mEKernelCPU, global_ws, local_ws );
					
			mQueueCPU->ReadBuffer( Result, sizeof( char ) * aData.size(), &result[0] );
			
			return result;
		}
		
		const DataArray OpenCL::GPUEncrypt( const DataArray& data ) {
			DataArray aData( data.begin(), data.end() ), rKey = mKey.Value();
							
			Buffer RoundKey( *mContextGPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * rKey.size(), &rKey[0] );
			Buffer Input( *mContextGPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * aData.size(), &aData[0] );
			Buffer Result( *mContextGPU, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * aData.size(), 0 );
			
			const unsigned int dataSize = aData.size();
			
			bool paramSuccess = mEKernelGPU->Parameter( 0, RoundKey );
			paramSuccess |= mEKernelGPU->Parameter( 1, Input );
			paramSuccess |= mEKernelGPU->Parameter( 2, Result );
			
			if( !paramSuccess ) {
				std::cerr << "Parameters Invalid" << std::endl;
				throw std::exception();
			}
			
			const size_t local_ws = 1;
			const size_t global_ws = dataSize / 16;

			DataArray result( dataSize );
			mQueueGPU->RangeKernel( *mEKernelGPU, global_ws, local_ws );
					
			mQueueGPU->ReadBuffer( Result, sizeof( char ) * aData.size(), &result[0] );
			
			return result;
		}
		
		const DataArray OpenCL::CPUDecrypt( const DataArray& data ) {
			DataArray aData( data.begin(), data.end() ), rKey = mKey.Value();
				
			Buffer RoundKey( *mContextCPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * rKey.size(), &rKey[0] );
			Buffer Input( *mContextCPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * aData.size(), &aData[0] );
			Buffer Result( *mContextCPU, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * aData.size(), 0 );
			
			const unsigned int dataSize = aData.size();
			
			bool paramSuccess = mDKernelCPU->Parameter( 0, RoundKey );
			paramSuccess |= mDKernelCPU->Parameter( 1, Input );
			paramSuccess |= mDKernelCPU->Parameter( 2, Result );
			
			if( !paramSuccess ) {
				std::cerr << "Parameters Invalid" << std::endl;
				throw std::exception();
			}
			
			const size_t local_ws = 1;
			const size_t global_ws = dataSize / 16;

			DataArray result( dataSize );
			mQueueCPU->RangeKernel( *mDKernelCPU, global_ws, local_ws );
					
			mQueueCPU->ReadBuffer( Result, sizeof( char ) * aData.size(), &result[0] );
			
			return result;
		}
		
		const DataArray OpenCL::GPUDecrypt( const DataArray& data ) {
			DataArray aData( data.begin(), data.end() ), rKey = mKey.Value();
				
			Buffer RoundKey( *mContextGPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * rKey.size(), &rKey[0] );
			Buffer Input( *mContextGPU, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof( unsigned char ) * aData.size(), &aData[0] );
			Buffer Result( *mContextGPU, CL_MEM_WRITE_ONLY, sizeof( unsigned char ) * aData.size(), 0 );
			
			const unsigned int dataSize = aData.size();
			
			bool paramSuccess = mDKernelGPU->Parameter( 0, RoundKey );
			paramSuccess |= mDKernelGPU->Parameter( 1, Input );
			paramSuccess |= mDKernelGPU->Parameter( 2, Result );
			
			if( !paramSuccess ) {
				std::cerr << "Parameters Invalid" << std::endl;
				throw std::exception();
			}
			
			const size_t local_ws = 1;
			const size_t global_ws = dataSize / 16;

			DataArray result( dataSize );
			mQueueGPU->RangeKernel( *mDKernelGPU, global_ws, local_ws );
					
			mQueueGPU->ReadBuffer( Result, sizeof( char ) * aData.size(), &result[0] );
			
			return result;
		}
	}
}
