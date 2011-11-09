#include <vector>
#include <fstream>
#include <cstdlib>
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

void PrintTotal( std::ostream& stream, std::string name, timeval tStart, timeval tEnd ){
	long tDiff = ( ( tEnd.tv_sec - tStart.tv_sec ) * 1000 + ( (tEnd.tv_usec - tStart.tv_usec) / 1000.0 ) ) + 0.5;
	
	stream << name << " completed in " << tDiff << "ms" << std::endl;;
}

void BenchmarkEncryption( const std::string& name, const DataArray& data, CryptoCL::Cipher& cipher ){
	std::string fileName = "results_" + name + "_encryption.txt";
	std::ofstream stream( fileName.c_str() );

	timeval tStart, tEnd, tStartTotal;	
	gettimeofday( &tStartTotal, 0 );
	
	unsigned int size = 16;
	while( size < data.size() ){
		stream << size << " ";
		
		const DataArray dData( data.begin(), data.begin() + size );
		
		gettimeofday( &tStart, 0 );
		const DataArray encrypted = cipher.Encrypt( dData );
		gettimeofday( &tEnd, 0 );
		
		PrintResult(stream, tStart, tEnd);
		
		stream << std::endl;
		
		size += 16;
	}
	
	timeval tEndTotal;
	gettimeofday( &tEndTotal, 0 );
	
	PrintTotal( std::cout, name + "_encryption", tStartTotal, tEndTotal );
}

void BenchmarkDecryption( const std::string& name, const DataArray& data, CryptoCL::Cipher& cipher ){
	std::string fileName = "results_" + name + "_decryption.txt";
	std::ofstream stream( fileName.c_str() );

	timeval tStart, tEnd, tStartTotal;	
	gettimeofday( &tStartTotal, 0 );
	
	unsigned int size = 16;
	while( size < data.size() ){
		stream << size << " ";
		
		const DataArray eData( data.begin(), data.begin() + size );
		
		gettimeofday( &tStart, 0 );
		const DataArray dData = cipher.Decrypt( eData );
		gettimeofday( &tEnd, 0 );
		
		PrintResult(stream, tStart, tEnd);
		
		stream << std::endl;
		
		size += 16;
	}
	
	timeval tEndTotal;
	gettimeofday( &tEndTotal, 0 );
	
	PrintTotal( std::cout, name+ "_decryption", tStartTotal, tEndTotal );
}

enum Mode{ Encryption, Decryption, Both };

void Benchmark( const Mode mode, const std::string& name, const DataArray& data, CryptoCL::Cipher& cipher ){
	if( mode == Encryption || mode == Both ) BenchmarkEncryption( name, data, cipher );
	const DataArray eData = cipher.Encrypt( data );
	if( mode == Decryption || mode == Both ) BenchmarkDecryption( name, eData, cipher );
}

int main( int argc, char* argv[] ) {
	const unsigned int dataSize = 16*1024;
	DataArray data( dataSize );
	
	Mode mode = Both;
	
	if( argc > 1 ){
		if( std::string( argv[1] ) == "-enc" ) mode = Encryption;
		if( std::string( argv[1] ) == "-dec" ) mode = Decryption;
	}
	
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
	
	Benchmark(mode, "reference", data, cipher);
	
	Reference cipherCBC( Block::Mode::CipherBlockChaining, DataArray( iv, iv + 16 ) );
	cipherCBC.Initialise( rKey );
	
	Benchmark(mode, "reference_cbc", data, cipherCBC);
	
	OpenCL cpuCipher( OpenCL::CPU );
	cpuCipher.Initialise( rKey );
	
	Benchmark(mode, "opencl_cpu", data, cpuCipher );
	
	OpenCL cpuCipherCBC( OpenCL::CPU, Block::Mode::CipherBlockChaining, DataArray( iv, iv + 16 ) );
	cpuCipherCBC.Initialise( rKey );
	
	Benchmark(mode, "opencl_cpu_cbc", data, cpuCipherCBC );
	
	OpenCL gpuCipher( OpenCL::GPU );
	gpuCipher.Initialise( rKey );
	
	Benchmark(mode, "opencl_gpu", data, gpuCipher );
	
	OpenCL gpuCipherCBC( OpenCL::GPU, Block::Mode::CipherBlockChaining, DataArray( iv, iv + 16 ) );
	gpuCipherCBC.Initialise( rKey );
	
	Benchmark(mode, "opencl_gpu_cbc", data, gpuCipherCBC );
		
	return 0;
} 