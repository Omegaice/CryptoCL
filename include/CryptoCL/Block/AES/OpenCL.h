#ifndef CRYPTOCL_AES_OPENCL_H_
#define CRYPTOCL_AES_OPENCL_H_

#include <map>
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
			typedef std::map<Mode::BlockMode,tqd::Compute::OpenCL::Program> ProgramMap;
			
			class OpenCL : public AESBlockCipher {
				public:
					enum EDevice { CPU, GPU };
				protected:
					tqd::Compute::OpenCL::Queue *mQueue;
					tqd::Compute::OpenCL::Context *mContext;
					ProgramMap mEncryption, mDecryption;
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
			};
			
			struct DeviceUnavailiable : public std::exception {
				const char* what() const throw();
			};
		}
	}
}

#endif // CRYPTOCL_AES_OPENCL_H_
