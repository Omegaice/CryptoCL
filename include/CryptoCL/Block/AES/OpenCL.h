#ifndef CRYPTOCL_AES_OPENCL_H_
#define CRYPTOCL_AES_OPENCL_H_

#include <exception>
#include "CryptoCL/Block/AES/Base.h"

namespace tqd{
	namespace Compute{
		namespace OpenCL{
			class Context;
			class Buffer;
			class Queue;
			class Kernel;
			class PlatformManager;
		}
	}
}

namespace CryptoCL {
	namespace Block {
		namespace AES {
			class OpenCL : public Base {
				public:
					enum EDevice { CPU, GPU };
				protected:
					EDevice mDevice;
					tqd::Compute::OpenCL::Queue *mQueue;
					tqd::Compute::OpenCL::Kernel *mKernelE, *mKernelD;
					tqd::Compute::OpenCL::Context *mContext;
					tqd::Compute::OpenCL::PlatformManager *mPlatformManager;
				public:
					OpenCL( const EDevice device );
					~OpenCL();
					
					const DataArray Encrypt( const DataArray& data );
					const DataArray Decrypt( const DataArray& data );
				protected:
					void OnInitialise( const RoundKey& key );
			};
			
			struct DeviceUnavailiable : public std::exception {
				const char* what() const throw();
			};
		}
	}
}

#endif // CRYPTOCL_AES_OPENCL_H_
