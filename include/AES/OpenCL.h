#ifndef AES_OPENCL_H_
#define AES_OPENCL_H_

#include "AES/Base.h"

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

namespace AES {
	class OpenCL : public Base {
		protected:
			bool mCPU, mGPU;
			tqd::Compute::OpenCL::Queue *mQueueCPU, *mQueueGPU;
			tqd::Compute::OpenCL::Kernel *mEKernelCPU, *mDKernelCPU, *mEKernelGPU, *mDKernelGPU;
			tqd::Compute::OpenCL::Context *mContextCPU, *mContextGPU;
			tqd::Compute::OpenCL::PlatformManager *mPlatformManager;
		public:
			OpenCL();
			~OpenCL();
			
			void Initialise( const CharArray& key );
			
			bool isCPUAvailiable() const;
			bool isGPUAvailiable() const;
			
			const CharArray CPUEncrypt( const CharArray& data );
			const CharArray GPUEncrypt( const CharArray& data );
			
			const CharArray CPUDecrypt( const CharArray& data );
			const CharArray GPUDecrypt( const CharArray& data );
		private:
			void InitialiseCPU();
			void InitialiseGPU();
	};
}

#endif // AES_OPENCL_H_
