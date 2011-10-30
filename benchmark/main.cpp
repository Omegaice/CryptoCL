#include <vector>
#include <fstream>
#include <iostream>
#include <sys/time.h>

#include <CryptoCL/Block/AES/OpenCL.h>
#include <CryptoCL/Block/AES/Reference.h>

using namespace CryptoCL;
using namespace CryptoCL::Block::AES;

void PrintResult( std::ostream& stream, timeval tStart, timeval tEnd ){
	long tDiff = ( ( tEnd.tv_sec - tStart.tv_sec ) * 1000 + ( (tEnd.tv_usec - tStart.tv_usec) / 1000.0 ) ) + 0.5;
	
	stream << tDiff << " ";
}

void Benchmark( const std::string& name, const DataArray& data, CryptoCL::Cipher& cipher ){
	std::string fileName = "results_" + name + ".txt";
	std::ofstream stream( fileName.c_str() );
	
	const size_t dataSize = data.size();
	
	timeval tStart, tEnd, tStartTotal, tEndTotal;
	
	gettimeofday( &tStartTotal, 0 );
	
	unsigned int size = 16;
	while( size < dataSize ){
		stream << size << " ";
		
		gettimeofday( &tStart, 0 );
		const DataArray encrypted = cipher.Encrypt( DataArray( data.begin(), data.begin() + size ) );
		gettimeofday( &tEnd, 0 );
		
		PrintResult(stream, tStart, tEnd);
	
		gettimeofday( &tStart, 0 );
		const DataArray decrypted = cipher.Decrypt( encrypted );
		gettimeofday( &tEnd, 0 );
		
		PrintResult(stream, tStart, tEnd);
		
		stream << std::endl;
		
		size += 16;
	}
	
	gettimeofday( &tEndTotal, 0 );
	
	stream.close();
	
	long tDiff = ( ( tEndTotal.tv_sec - tStartTotal.tv_sec ) * 1000 + ( (tEndTotal.tv_usec - tStartTotal.tv_usec) / 1000.0 ) ) + 0.5;
	std::cout << name << " completed in " << tDiff << "ms" << std::endl;
}

int main() {
	const unsigned int dataSize = 16*1024;
	
	std::vector<unsigned char> data;
	data.resize( dataSize );
	
	srand( time(0) );
	for( unsigned int i = 0; i < dataSize; i++ ){
		data[i] = rand();
	}
	
	const unsigned char key[] = { 
		0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
		0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
	};
	
	const unsigned char iv[] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
	};
		
	const RoundKey rKey( DataArray( key, key + 16 ) );
	
	Reference cipher;
	cipher.Initialise( rKey );
	
	Benchmark("reference", data, cipher);
	
	Reference cipherCBC( Block::Mode::CipherBlockChaining, DataArray( iv, iv + 16 ) );
	cipherCBC.Initialise( rKey );
	
	Benchmark("reference_cbc", data, cipherCBC);
	
	OpenCL cpuCipher( OpenCL::CPU );
	cpuCipher.Initialise( rKey );
	
	Benchmark("opencl_cpu", data, cpuCipher );
	
	OpenCL cpuCipherCBC( OpenCL::CPU, Block::Mode::CipherBlockChaining, DataArray( iv, iv + 16 ) );
	cpuCipherCBC.Initialise( rKey );
	
	Benchmark("opencl_cpu_cbc", data, cpuCipherCBC );
	
	OpenCL gpuCipher( OpenCL::GPU );
	gpuCipher.Initialise( rKey );
	
	Benchmark("opencl_gpu", data, gpuCipher );
	
	OpenCL gpuCipherCBC( OpenCL::GPU, Block::Mode::CipherBlockChaining, DataArray( iv, iv + 16 ) );
	gpuCipherCBC.Initialise( rKey );
	
	Benchmark("opencl_gpu_cbc", data, gpuCipherCBC );
		
	return 0;
} 