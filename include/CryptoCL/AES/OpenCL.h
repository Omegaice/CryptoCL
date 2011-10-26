#ifndef CRYPTOCL_AES_OPENCL_H_
#define CRYPTOCL_AES_OPENCL_H_

#include "CryptoCL/AES/Base.h"
#include "CryptoCL/AES/RoundKey.h"

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
	namespace AES {
		class OpenCL {
			protected:
				RoundKey mKey;
				bool mCPU, mGPU;
				tqd::Compute::OpenCL::Queue *mQueueCPU, *mQueueGPU;
				tqd::Compute::OpenCL::Kernel *mEKernelCPU, *mDKernelCPU, *mEKernelGPU, *mDKernelGPU;
				tqd::Compute::OpenCL::Context *mContextCPU, *mContextGPU;
				tqd::Compute::OpenCL::PlatformManager *mPlatformManager;
			public:
				OpenCL( const RoundKey& key );
				~OpenCL();
				
				bool isCPUAvailiable() const;
				bool isGPUAvailiable() const;
				
				const DataArray CPUEncrypt( const DataArray& data );
				const DataArray GPUEncrypt( const DataArray& data );
				
				const DataArray CPUDecrypt( const DataArray& data );
				const DataArray GPUDecrypt( const DataArray& data );
			private:
				void InitialiseCPU();
				void InitialiseGPU();
		};
	}
}

#endif // CRYPTOCL_AES_OPENCL_H_
