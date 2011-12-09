#include <ctime>
#include <cmath>
#include <vector>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <iostream>

#include "Timer.h"
#include <CryptoCL/Block/AES/OpenCL.h>
#include <CryptoCL/Block/AES/Reference.h>

using namespace CryptoCL;
using namespace CryptoCL::Block::AES;

const unsigned int PacketCount = 1;
const unsigned int AverageIterations = 20;
const unsigned int StepSize = 16;

void BenchmarkEncryption( const std::string& name, const DataArray& data, const CryptoCL::Cipher& cipher, const CryptoCL::Key& key, const DataArray& iv = DataArray() ){
	std::ostringstream fileName;
	fileName << "results_" << name << "_encryption.txt";

	std::ofstream stream( fileName.str().c_str() );

	Timer totalTime, loopTime;
	totalTime.start();
	
	unsigned int size = StepSize;
	while( size <= data.size() ){
		const DataArray dData( data.begin(), data.begin() + size );
		
		double average = 0.0;
		for( unsigned int i = 0; i < AverageIterations; i++ ){
			loopTime.start();
			for( unsigned int j = 0; j < PacketCount; j++ ){
				const DataArray encrypted = cipher.Encrypt( dData, key, iv );
			}
			loopTime.stop();
			
			average += loopTime.getElapsedTimeInMilliSec();
		}
		average /= AverageIterations;

		stream << size << " " << average << std::endl;
		
		size += StepSize;
	}
	
	totalTime.stop();
	
	std::cout << name << "_encryption completed in " << totalTime.getElapsedTimeInMilliSec() << "ms" << std::endl;
}

void BenchmarkEncryptionMulti( const std::string& name, const DataArray& data, const CryptoCL::Cipher& cipher, const CryptoCL::Key& key, const DataArray& iv = DataArray() ){
	std::ostringstream fileName;
	fileName << "results_" << name << "multi__encryption.txt";

	std::ofstream stream( fileName.str().c_str() );
	
	KeyVector avKey;
	for( unsigned int i = 0; i < PacketCount; i++ ){
		avKey.push_back( &key );
	}

	Timer totalTime, loopTime;
	totalTime.start();
	
	unsigned int size = StepSize;
	while( size <= data.size() ){
		const DataArray dData( data.begin(), data.begin() + size );
		
		ArrayVector avData;
		for( unsigned int i = 0; i < PacketCount; i++ ){
			avData.push_back( dData );
		}
		
		ArrayVector avIV;
		if( iv.size() > 0 ){
			for( unsigned int i = 0; i < PacketCount; i++ ){
				avIV.push_back( DataArray( iv.begin(), iv.begin() + size ) );
			}
		}
		
		double average = 0.0;
		for( unsigned int i = 0; i < AverageIterations; i++ ){
			loopTime.start();
			if( iv.size() > 0 ){
				cipher.Encrypt( avData, avKey, avIV );
			}else{
				cipher.Encrypt( avData, avKey);
			}
			loopTime.stop();
			
			average += loopTime.getElapsedTimeInMilliSec();
		}
		average /= AverageIterations;

		stream << size << " " << average << std::endl;
		
		size += StepSize;
	}
	
	totalTime.stop();
	
	std::cout << name << "_encryption completed in " << totalTime.getElapsedTimeInMilliSec() << "ms" << std::endl;
}

void BenchmarkDecryption( const std::string& name, const DataArray& data, const CryptoCL::Cipher& cipher, const CryptoCL::Key& key, const DataArray& iv = DataArray() ){
	std::ostringstream fileName;
	fileName << "results_" << name << "_decryption.txt";

	std::ofstream stream( fileName.str().c_str() );

	Timer totalTime, loopTime;
	totalTime.start();
	
	unsigned int size = StepSize;
	while( size <= data.size() ){
		const DataArray eData( data.begin(), data.begin() + size );
		
		double average = 0.0;
		for( unsigned int i = 0; i < AverageIterations; i++ ){
			loopTime.start();
			const DataArray decrypted = cipher.Decrypt( eData, key, iv );
			loopTime.stop();
			
			average += loopTime.getElapsedTimeInMilliSec();
		}
		average /= AverageIterations;
		
		stream << size << " " << average << std::endl;
		
		size += StepSize;
	}

	totalTime.stop();
	
	std::cout << name << "_decryption completed in " << totalTime.getElapsedTimeInMilliSec() << "ms" << std::endl;
}

void BenchmarkDecryptionMulti( const std::string& name, const DataArray& data, const CryptoCL::Cipher& cipher, const CryptoCL::Key& key, const DataArray& iv = DataArray() ){
	std::ostringstream fileName;
	fileName << "results_" << name << "multi__decryption.txt";

	std::ofstream stream( fileName.str().c_str() );
	
	KeyVector avKey;
	for( unsigned int i = 0; i < PacketCount; i++ ){
		avKey.push_back( &key );
	}

	Timer totalTime, loopTime;
	totalTime.start();
	
	unsigned int size = StepSize;
	while( size <= data.size() ){
		const DataArray dData( data.begin(), data.begin() + size );
		
		ArrayVector avData;
		for( unsigned int i = 0; i < PacketCount; i++ ){
			avData.push_back( dData );
		}
		
		ArrayVector avIV;
		if( iv.size() > 0 ){
			for( unsigned int i = 0; i < PacketCount; i++ ){
				avIV.push_back( DataArray( iv.begin(), iv.begin() + size ) );
			}
		}
		
		double average = 0.0;
		for( unsigned int i = 0; i < AverageIterations; i++ ){
			loopTime.start();
			if( iv.size() > 0 ){
				cipher.Decrypt( avData, avKey, avIV );
			}else{
				cipher.Decrypt( avData, avKey);
			}
			loopTime.stop();
			
			average += loopTime.getElapsedTimeInMilliSec();
		}
		average /= AverageIterations;

		stream << size << " " << average << std::endl;
		
		size += StepSize;
	}
	
	totalTime.stop();
	
	std::cout << name << "_encryption completed in " << totalTime.getElapsedTimeInMilliSec() << "ms" << std::endl;
}

enum Mode{ Encryption, Decryption, Both };

void Benchmark( const Mode mode, const std::string& name, const DataArray& dData, const DataArray& eData, const CryptoCL::Cipher& cipher, const CryptoCL::Key& key, const DataArray& iv = DataArray() ){
	if( mode == Encryption || mode == Both ) {
		//BenchmarkEncryption( name, dData, cipher, key, iv );
		//BenchmarkEncryptionMulti( name, dData, cipher, key, iv );
	}
	if( mode == Decryption || mode == Both ) {
		BenchmarkDecryption( name, eData, cipher, key, iv );
		//BenchmarkDecryptionMulti( name, eData, cipher, key, iv );
	}
}

int main( int argc, char* argv[] ) {
	const unsigned int dataSize = 16*1024;
	DataArray dData( dataSize );
	
	Mode mode = Both;
	
	if( argc > 1 ){
		if( std::string( argv[1] ) == "-enc" ) mode = Encryption;
		if( std::string( argv[1] ) == "-dec" ) mode = Decryption;
	}
	
	srand( std::time(0) );
	for( unsigned int i = 0; i < dataSize; i++ ) dData[i] = rand();
	
	const unsigned char key[] = { 
		0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
		0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
	};
	
	const unsigned char iv[] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
	};
		
	const DataArray dIV( iv, iv + 16 );
	const RoundKey rKey( DataArray( key, key + 32 ) );
	
	Reference cipherCBC( Block::Mode::CipherBlockChaining );
	const DataArray eCBCData = cipherCBC.Encrypt( dData, rKey, dIV );
	
	Benchmark(mode, "reference_cbc", dData, eCBCData, cipherCBC, rKey, dIV );
	
	try{
		OpenCL gpuCipherCBC( OpenCL::GPU, Block::Mode::CipherBlockChaining );
		Benchmark(mode, "opencl_gpu_cbc", dData, eCBCData, gpuCipherCBC, rKey, dIV );
	}catch( DeviceUnavailiable& e ){
		
	}
		
	return 0;
} 