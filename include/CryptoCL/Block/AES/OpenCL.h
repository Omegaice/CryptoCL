#ifndef CRYPTOCL_AES_OPENCL_H_
#define CRYPTOCL_AES_OPENCL_H_

#include <exception>
#include "CryptoCL/Block/AES/AESBlockCipher.h"

namespace tqd{
	namespace Compute{
		namespace OpenCL{
			class Queue;
			class Device;
			class Program;
			class Context;
		}
	}
}

namespace CryptoCL {
	namespace Block {
		namespace AES {
			class OpenCL : public AESBlockCipher {
				public:
					enum EDevice { CPU, GPU };
				protected:
					tqd::Compute::OpenCL::Queue *mQueue;
					tqd::Compute::OpenCL::Context *mContext;
					tqd::Compute::OpenCL::Program *mEncryption, *mDecryption, *mDecryptionCBC;
				public:
					OpenCL( const EDevice deviceType, const Mode::BlockMode mode = Mode::ElectronicCookBook, const DataArray& iv = DataArray() );
					OpenCL( tqd::Compute::OpenCL::Device& device, const Mode::BlockMode mode = Mode::ElectronicCookBook, const DataArray& iv = DataArray() );
					
					OpenCL( const OpenCL& other );
					OpenCL& operator=( const OpenCL& other );
					
					~OpenCL();
					
					const DataArray Encrypt( const DataArray& data );
					const DataArray Decrypt( const DataArray& data );
				protected:
					void OnInitialise( const RoundKey& key );
					void Setup( tqd::Compute::OpenCL::Device& device );
			};
			
			struct DeviceUnavailiable : public std::exception {
				const char* what() const throw();
			};
		}
	}
}

#endif // CRYPTOCL_AES_OPENCL_H_
