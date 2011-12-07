#ifndef CRYPTOCL_AES_OPENCL_H_
#define CRYPTOCL_AES_OPENCL_H_

#include <map>
#include <exception>
#include <TQD/Compute/OpenCL/Event.h>
#include <TQD/Compute/OpenCL/Program.h>
#include "CryptoCL/Block/AES/AESBlockCipher.h"

namespace tqd{
	namespace Compute{
		namespace OpenCL{
			class Queue;
			class Device;
			class Program;
			class Context;
			class ReadOnlyBuffer;
			class ReadWriteBuffer;
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
					tqd::Compute::OpenCL::Program mEncryption, mDecryption, mCBC;
				public:
					OpenCL( const EDevice deviceType, const Mode::BlockMode mode = Mode::ElectronicCookBook );
					OpenCL( tqd::Compute::OpenCL::Device& device, const Mode::BlockMode mode = Mode::ElectronicCookBook );
					
					OpenCL( const OpenCL& other );
					OpenCL& operator=( const OpenCL& other );
					
					~OpenCL();
					
					const DataArray Encrypt( const DataArray& data, const CryptoCL::Key& key, const DataArray& iv = DataArray() ) const;
					const ArrayVector Encrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv = ArrayVector() ) const;
					
					const DataArray Decrypt( const DataArray& data, const CryptoCL::Key& key, const DataArray& iv = DataArray() ) const;
					const ArrayVector Decrypt( const ArrayVector& data, const KeyVector& key, const ArrayVector& iv = ArrayVector() ) const;
				protected:
					void Setup( tqd::Compute::OpenCL::Device& device );
					
					const tqd::Compute::OpenCL::Event 
					EncryptBlock( const tqd::Compute::OpenCL::Buffer& key, 
						const tqd::Compute::OpenCL::Buffer& input, 
						const tqd::Compute::OpenCL::Buffer& result, 
						unsigned int rounds, unsigned int block,
						const tqd::Compute::OpenCL::Event& event = tqd::Compute::OpenCL::Event() ) const;
						
					const tqd::Compute::OpenCL::Event 
					EncryptChunk( const DataArray& data, DataArray& result, 
						const CryptoCL::Key& key, const DataArray& iv = DataArray() ) const;
					
					const tqd::Compute::OpenCL::Event 
					EncryptChunkCBC( const DataArray& data, DataArray& result, 
						const CryptoCL::Key& key, const DataArray& iv = DataArray() ) const;
						
					const tqd::Compute::OpenCL::Event 
					DecryptChunk( const DataArray& data, DataArray& result, const CryptoCL::Key& key ) const;
					
					const tqd::Compute::OpenCL::Event 
					DecryptChunkCBC( const DataArray& data, DataArray& result, const CryptoCL::Key& key, const DataArray& iv ) const;
						
					const tqd::Compute::OpenCL::Event 
					XORBlock( const tqd::Compute::OpenCL::Buffer& block, const size_t blockOffset,
						const tqd::Compute::OpenCL::Buffer& value, const size_t valOffset, 
						const tqd::Compute::OpenCL::Event& event ) const;
			};
			
			struct DeviceUnavailiable : public std::exception {
				const char* what() const throw();
			};
		}
	}
}

#endif // CRYPTOCL_AES_OPENCL_H_
