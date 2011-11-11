#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <sys/time.h>

#include "TQD/Compute/OpenCL/DeviceList.h"
#include "TQD/Compute/OpenCL/PlatformList.h"

#include "CryptoCL/Block/AES/OpenCL.h"

using namespace CryptoCL;
using namespace CryptoCL::Block::AES;
using namespace tqd::Compute::OpenCL;

int main (int argc, char* argv[])
{
	bool bPlatform = false;
	bool bDevice = false;
	unsigned int deviceNumber = 0;
	unsigned int platformNumber = 0;
	cl_device_type devType = CL_DEVICE_TYPE_ALL;
	
	/* Arguments */
	for( unsigned int i = 1; i < argc; i++ ){
		std::string param( argv[i] );
		
		if( param == "-platformid" ){
			std::istringstream stream( argv[i+1] );
			stream >> platformNumber;
			
			bPlatform = true;
			i++;
		}
		
		if( param == "-deviceid" ){
			std::istringstream stream( argv[i+1] );
			stream >> deviceNumber;
			
			bDevice = true;
			i++;
		}
		
		if( param == "-devicelist" ){
			PlatformList platformList;
			
			const unsigned int platforms = platformList.Count();
			for( unsigned int i = 0; i < platforms; i++ ){
				DeviceList devList( platformList.GetPlatform( i ) );
				
				std::cout << "Platform[" << i << "] " << platformList.GetPlatform( i ).Name() << std::endl;
				
				const unsigned int devices = devList.Count();
				for( unsigned int j = 0; j < devices; j++ ){
					Device temp = devList.GetDevice( j );
					
					cl_device_type type;
					temp.InfoData( CL_DEVICE_TYPE, &type );
					
					if( type == devType || devType == CL_DEVICE_TYPE_ALL ) {
						std::cout << "\tDevice[" << j << "] " << temp.InfoString(CL_DEVICE_NAME) << std::endl;
					}
				}
			}
			
			return EXIT_SUCCESS;
		}
	}
	
	/* OpenCL Setup */
	Device device;
	
	PlatformList platList;
	Platform platform( 0 );
	
	if( !bPlatform ){
		platform = platList.GetPlatform( 0 );
	}else{
		if( platList.Count() < platformNumber ){
			std::cerr << "Invalid Platform Selected" << std::endl;
			return EXIT_FAILURE;
		}else{
			platform = platList.GetPlatform( platformNumber );
		}
	}
	
	DeviceList devList( platform );
	if( !bDevice ) {
		device = devList.GetDevice( 0 );
	}else{
		if( devList.Count() < deviceNumber ){
			std::cerr << "Invalid Device Selected" << std::endl;
			return EXIT_FAILURE;
		}else{
			device = devList.GetDevice( deviceNumber );
		}
	}
	
	std::cout << "Selected Platform: " << platform.Name() << std::endl;
	std::cout << "\tSelected Device: " << device.InfoString( CL_DEVICE_NAME ) << std::endl;
	
	/* Code Setup */
	timeval startTime;
	gettimeofday( &startTime, 0 );
	
	const size_t keySize = 32;
	const size_t dataSize = 1024 * 1024; // 1MB
	
	std::vector<unsigned char> key( keySize );
	for( size_t i = 0; i < keySize; i++ ){
		key[i] = rand();
	}
	
	std::vector<unsigned char> dData( dataSize );
	for( size_t i = 0; i < dataSize; i++ ){
		dData[i] = rand();
	}
				
	OpenCL cipher( device );
	cipher.Initialise( RoundKey( key ) );
	
	std::vector<unsigned char> eData = cipher.Encrypt( dData );
	
	while( true ){
		std::vector<unsigned char> decrypt = cipher.Decrypt( eData );
		for( size_t i = 0; i < dataSize; i++ ){
			if( decrypt[i] != dData[i] ) {
				timeval endTime;
				gettimeofday( &endTime, 0 );
				
				std::cerr << "Memory Error after " << (endTime.tv_sec - startTime.tv_sec ) << std::endl;
				return 1;
			}
		}	
		
		sleep(0);
	}
	
	return 0;
}
