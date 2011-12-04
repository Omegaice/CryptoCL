#include "AES/OpenCLTest.h"

#include <iomanip>
#include <iostream>
#include <CryptoCL/Block/AES/RoundKey.h>
#include <CryptoCL/Block/AES/OpenCL.h>
#include <cppunit/extensions/HelperMacros.h>

CPPUNIT_TEST_SUITE_REGISTRATION( AES::OpenCLTest );

namespace AES {
	using namespace CryptoCL;
	using namespace CryptoCL::Block::AES;
	
	// 128 Bit Tests
	static unsigned char Key128[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	
	static unsigned char CBCKey128[] = { 
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	
	static unsigned char CBCIV128[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	
	static DataArray IVArray128( CBCIV128, CBCIV128 + 16 );
	static RoundKey RoundKey128( DataArray( Key128, Key128 + 16 ) );
	static RoundKey CBCRoundKey128( DataArray( CBCKey128, CBCKey128 + 16 ) );
	
	void OpenCLTest::testEncryption128CPU() {
		const unsigned char data[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		const unsigned char expected[] = {
			0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
		};
		
		try{
			OpenCL cipher( OpenCL::CPU );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 16 ), RoundKey128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryptionCBC128CPU() {
		const unsigned char data[] = { 
			0x94, 0x9f, 0x22, 0xbb, 0xe9, 0xaa, 0x15, 0xbc, 0x12, 0x4b, 0x3d, 0x71, 0xc3, 0xf2, 0xd9, 0xa1, 
			0x53, 0x4c, 0x8c, 0x4b, 0x7c, 0x10, 0x7c, 0x36, 0xf7, 0x28, 0xff, 0xc0, 0xee, 0x50, 0x63, 0xe5
		};
		
		const unsigned char expected[] = {
			0x7c, 0x39, 0xc9, 0x12, 0xb3, 0x8f, 0xef, 0x32, 0x49, 0x20, 0x1d, 0x93, 0xcf, 0x7f, 0xa9, 0xbe, 
			0x2e, 0x28, 0xd9, 0x9a, 0xfb, 0xfb, 0x36, 0x69, 0x68, 0xf3, 0x0b, 0xa0, 0x18, 0xed, 0x48, 0x59
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 32 ), CBCRoundKey128, IVArray128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryption128CPU() {
		const unsigned char data[] = {
			0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
		};
		
		const unsigned char expected[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		try{
			OpenCL cipher( OpenCL::CPU );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 16 ), RoundKey128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}

	void OpenCLTest::testDecryptionCBC128CPU() {
		const unsigned char data[] = {
			0x7c, 0x39, 0xc9, 0x12, 0xb3, 0x8f, 0xef, 0x32, 0x49, 0x20, 0x1d, 0x93, 0xcf, 0x7f, 0xa9, 0xbe, 
			0x2e, 0x28, 0xd9, 0x9a, 0xfb, 0xfb, 0x36, 0x69, 0x68, 0xf3, 0x0b, 0xa0, 0x18, 0xed, 0x48, 0x59
		};
		
		const unsigned char expected[] = { 
			0x94, 0x9f, 0x22, 0xbb, 0xe9, 0xaa, 0x15, 0xbc, 0x12, 0x4b, 0x3d, 0x71, 0xc3, 0xf2, 0xd9, 0xa1, 
			0x53, 0x4c, 0x8c, 0x4b, 0x7c, 0x10, 0x7c, 0x36, 0xf7, 0x28, 0xff, 0xc0, 0xee, 0x50, 0x63, 0xe5
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 16 ), CBCRoundKey128, IVArray128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryption128GPU() {
		const unsigned char data[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		const unsigned char expected[] = {
			0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
		};
		
		try{
			OpenCL cipher( OpenCL::GPU );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 16 ), RoundKey128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryptionCBC128GPU() {
		const unsigned char data[] = { 
			0x94, 0x9f, 0x22, 0xbb, 0xe9, 0xaa, 0x15, 0xbc, 0x12, 0x4b, 0x3d, 0x71, 0xc3, 0xf2, 0xd9, 0xa1, 
			0x53, 0x4c, 0x8c, 0x4b, 0x7c, 0x10, 0x7c, 0x36, 0xf7, 0x28, 0xff, 0xc0, 0xee, 0x50, 0x63, 0xe5
		};
		
		const unsigned char expected[] = {
			0x7c, 0x39, 0xc9, 0x12, 0xb3, 0x8f, 0xef, 0x32, 0x49, 0x20, 0x1d, 0x93, 0xcf, 0x7f, 0xa9, 0xbe, 
			0x2e, 0x28, 0xd9, 0x9a, 0xfb, 0xfb, 0x36, 0x69, 0x68, 0xf3, 0x0b, 0xa0, 0x18, 0xed, 0x48, 0x59
		};
		
		try{
			OpenCL cipher( OpenCL::GPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 32 ), CBCRoundKey128, IVArray128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryption128GPU() {
		const unsigned char data[] = {
			0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
		};
		
		const unsigned char expected[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		try{
			OpenCL cipher( OpenCL::GPU );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 16 ), RoundKey128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}	
	
	void OpenCLTest::testDecryptionCBC128GPU() {
		const unsigned char data[] = {
			0x7c, 0x39, 0xc9, 0x12, 0xb3, 0x8f, 0xef, 0x32, 0x49, 0x20, 0x1d, 0x93, 0xcf, 0x7f, 0xa9, 0xbe, 
			0x2e, 0x28, 0xd9, 0x9a, 0xfb, 0xfb, 0x36, 0x69, 0x68, 0xf3, 0x0b, 0xa0, 0x18, 0xed, 0x48, 0x59
		};
		
		const unsigned char expected[] = { 
			0x94, 0x9f, 0x22, 0xbb, 0xe9, 0xaa, 0x15, 0xbc, 0x12, 0x4b, 0x3d, 0x71, 0xc3, 0xf2, 0xd9, 0xa1, 
			0x53, 0x4c, 0x8c, 0x4b, 0x7c, 0x10, 0x7c, 0x36, 0xf7, 0x28, 0xff, 0xc0, 0xee, 0x50, 0x63, 0xe5
		};
		
		try{
			OpenCL cipher( OpenCL::GPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 32 ), CBCRoundKey128, IVArray128 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	// 192 Bit Tests
	static unsigned char Key192[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
	};
	
	static unsigned char CBCKey192[] = { 
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
	};
	
	static unsigned char CBCIV192[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	
	static DataArray IVArray192( CBCIV192, CBCIV192 + 16 );
	static RoundKey RoundKey192( DataArray( Key192, Key192 + 24 ) );
	static RoundKey CBCRoundKey192( DataArray( CBCKey192, CBCKey192 + 24 ) );
	
	void OpenCLTest::testEncryption192CPU() {
		const unsigned char data[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		const unsigned char expected[] = {
			0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91 
		};
		
		try{
			OpenCL cipher( OpenCL::CPU );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 16 ), RoundKey192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}

	void OpenCLTest::testEncryptionCBC192CPU() {
		const unsigned char data[] = { 
			0x69, 0xdc, 0x07, 0xf9, 0xd4, 0x05, 0x45, 0x83, 0x59, 0x6d, 0x77, 0x81, 0x45, 0x20, 0x20, 0xa5, 
			0x08, 0xc0, 0xc7, 0xc0, 0xf3, 0xd0, 0x72, 0xce, 0x58, 0x26, 0x84, 0x7f, 0x4f, 0xfd, 0x01, 0xd6
		};
		
		const unsigned char expected[] = {
			0x46, 0xcb, 0xa5, 0xc5, 0x9d, 0x69, 0xee, 0x30, 0x17, 0xa2, 0xfa, 0x1e, 0x37, 0xfb, 0x15, 0xed, 
			0xe3, 0x2b, 0x06, 0x61, 0xec, 0xa8, 0x4b, 0x2b, 0xf8, 0x80, 0x88, 0x15, 0xac, 0x66, 0x30, 0x22
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 32 ), CBCRoundKey192, IVArray192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryption192CPU() {
		const unsigned char data[] = {
			0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91
		};
		
		const unsigned char expected[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		try{
			OpenCL cipher( OpenCL::CPU );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 16 ), RoundKey192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryptionCBC192CPU() {
		const unsigned char data[] = {
			0x46, 0xcb, 0xa5, 0xc5, 0x9d, 0x69, 0xee, 0x30, 0x17, 0xa2, 0xfa, 0x1e, 0x37, 0xfb, 0x15, 0xed, 
			0xe3, 0x2b, 0x06, 0x61, 0xec, 0xa8, 0x4b, 0x2b, 0xf8, 0x80, 0x88, 0x15, 0xac, 0x66, 0x30, 0x22
		};
		
		const unsigned char expected[] = { 
			0x69, 0xdc, 0x07, 0xf9, 0xd4, 0x05, 0x45, 0x83, 0x59, 0x6d, 0x77, 0x81, 0x45, 0x20, 0x20, 0xa5, 
			0x08, 0xc0, 0xc7, 0xc0, 0xf3, 0xd0, 0x72, 0xce, 0x58, 0x26, 0x84, 0x7f, 0x4f, 0xfd, 0x01, 0xd6
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 32 ), CBCRoundKey192, IVArray192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryption192GPU() {
		const unsigned char data[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		const unsigned char expected[] = {
			0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91 
		};
		
		try{
			OpenCL cipher( OpenCL::GPU );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 16 ), RoundKey192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryptionCBC192GPU() {
		const unsigned char data[] = { 
			0x69, 0xdc, 0x07, 0xf9, 0xd4, 0x05, 0x45, 0x83, 0x59, 0x6d, 0x77, 0x81, 0x45, 0x20, 0x20, 0xa5, 
			0x08, 0xc0, 0xc7, 0xc0, 0xf3, 0xd0, 0x72, 0xce, 0x58, 0x26, 0x84, 0x7f, 0x4f, 0xfd, 0x01, 0xd6
		};
		
		const unsigned char expected[] = {
			0x46, 0xcb, 0xa5, 0xc5, 0x9d, 0x69, 0xee, 0x30, 0x17, 0xa2, 0xfa, 0x1e, 0x37, 0xfb, 0x15, 0xed, 
			0xe3, 0x2b, 0x06, 0x61, 0xec, 0xa8, 0x4b, 0x2b, 0xf8, 0x80, 0x88, 0x15, 0xac, 0x66, 0x30, 0x22
		};
		
		try{
			OpenCL cipher( OpenCL::GPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 32 ), CBCRoundKey192, IVArray192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryption192GPU() {
		const unsigned char data[] = {
			0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91
		};
		
		const unsigned char expected[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		try{
			OpenCL cipher( OpenCL::GPU );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 16 ), RoundKey192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryptionCBC192GPU() {
		const unsigned char data[] = {
			0x46, 0xcb, 0xa5, 0xc5, 0x9d, 0x69, 0xee, 0x30, 0x17, 0xa2, 0xfa, 0x1e, 0x37, 0xfb, 0x15, 0xed, 
			0xe3, 0x2b, 0x06, 0x61, 0xec, 0xa8, 0x4b, 0x2b, 0xf8, 0x80, 0x88, 0x15, 0xac, 0x66, 0x30, 0x22
		};
		
		const unsigned char expected[] = { 
			0x69, 0xdc, 0x07, 0xf9, 0xd4, 0x05, 0x45, 0x83, 0x59, 0x6d, 0x77, 0x81, 0x45, 0x20, 0x20, 0xa5, 
			0x08, 0xc0, 0xc7, 0xc0, 0xf3, 0xd0, 0x72, 0xce, 0x58, 0x26, 0x84, 0x7f, 0x4f, 0xfd, 0x01, 0xd6
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 32 ), CBCRoundKey192, IVArray192 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	// 256 Bit Tests
	static unsigned char Key256[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f 
	};
	
	static unsigned char CBCKey256[] = { 
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};
	
	static unsigned char CBCIV256[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	
	static DataArray IVArray256( CBCIV256, CBCIV256 + 16 );
	static RoundKey RoundKey256( DataArray( Key256, Key256 + 32 ) );
	static RoundKey CBCRoundKey256( DataArray( CBCKey256, CBCKey256 + 32 ) );
	
	void OpenCLTest::testEncryption256CPU() {
		const unsigned char data[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		const unsigned char expected[] = {
			0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 
		};
		
		try{
			OpenCL cipher( OpenCL::CPU );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 16 ), RoundKey256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryptionCBC256CPU() {
		const unsigned char data[] = { 
			0xd9, 0x1b, 0xf9, 0xf3, 0x20, 0xf9, 0x3c, 0xa1, 0x79, 0xec, 0x3a, 0x74, 0xa4, 0xe3, 0x6e, 0xed, 
			0xd6, 0xd6, 0xca, 0xa9, 0x44, 0x61, 0x68, 0x5b, 0x36, 0xb6, 0x13, 0x6e, 0x8e, 0x6e, 0xa7, 0x00
		};
		
		const unsigned char expected[] = {
			0x11, 0x0e, 0x8a, 0xc4, 0x2c, 0x58, 0xf3, 0xce, 0x73, 0x37, 0xb8, 0xf0, 0x3c, 0x93, 0x04, 0x26, 
			0x45, 0xd2, 0x53, 0x12, 0xf8, 0x45, 0x61, 0x91, 0x81, 0x85, 0x5f, 0x50, 0x74, 0x9b, 0xed, 0x52
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 32 ), CBCRoundKey256, IVArray256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryption256CPU() {
		const unsigned char data[] = {
			0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 
		};
		
		const unsigned char expected[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		try{
			OpenCL cipher( OpenCL::CPU );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 16 ), RoundKey256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryptionCBC256CPU() {
		const unsigned char data[] = {
			0x11, 0x0e, 0x8a, 0xc4, 0x2c, 0x58, 0xf3, 0xce, 0x73, 0x37, 0xb8, 0xf0, 0x3c, 0x93, 0x04, 0x26, 
			0x45, 0xd2, 0x53, 0x12, 0xf8, 0x45, 0x61, 0x91, 0x81, 0x85, 0x5f, 0x50, 0x74, 0x9b, 0xed, 0x52
		};
		
		const unsigned char expected[] = { 
			0xd9, 0x1b, 0xf9, 0xf3, 0x20, 0xf9, 0x3c, 0xa1, 0x79, 0xec, 0x3a, 0x74, 0xa4, 0xe3, 0x6e, 0xed, 
			0xd6, 0xd6, 0xca, 0xa9, 0x44, 0x61, 0x68, 0x5b, 0x36, 0xb6, 0x13, 0x6e, 0x8e, 0x6e, 0xa7, 0x00
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 32 ), CBCRoundKey256, IVArray256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryption256GPU() {
		const unsigned char data[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		const unsigned char expected[] = {
			0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 
		};
		
		try{
			OpenCL cipher( OpenCL::GPU );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 16 ), RoundKey256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testEncryptionCBC256GPU() {
		const unsigned char data[] = { 
			0xd9, 0x1b, 0xf9, 0xf3, 0x20, 0xf9, 0x3c, 0xa1, 0x79, 0xec, 0x3a, 0x74, 0xa4, 0xe3, 0x6e, 0xed, 
			0xd6, 0xd6, 0xca, 0xa9, 0x44, 0x61, 0x68, 0x5b, 0x36, 0xb6, 0x13, 0x6e, 0x8e, 0x6e, 0xa7, 0x00
		};
		
		const unsigned char expected[] = {
			0x11, 0x0e, 0x8a, 0xc4, 0x2c, 0x58, 0xf3, 0xce, 0x73, 0x37, 0xb8, 0xf0, 0x3c, 0x93, 0x04, 0x26, 
			0x45, 0xd2, 0x53, 0x12, 0xf8, 0x45, 0x61, 0x91, 0x81, 0x85, 0x5f, 0x50, 0x74, 0x9b, 0xed, 0x52
		};
		
		try{
			OpenCL cipher( OpenCL::GPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Encrypt( DataArray( data, data + 32 ), CBCRoundKey256, IVArray256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}

	void OpenCLTest::testDecryption256GPU() {
		const unsigned char data[] = {
			0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 
		};
		
		const unsigned char expected[] = { 
			0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff 
		};
		
		try{
			OpenCL cipher( OpenCL::GPU );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 16 ), RoundKey256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
	
	void OpenCLTest::testDecryptionCBC256GPU() {
		const unsigned char data[] = {
			0x11, 0x0e, 0x8a, 0xc4, 0x2c, 0x58, 0xf3, 0xce, 0x73, 0x37, 0xb8, 0xf0, 0x3c, 0x93, 0x04, 0x26, 
			0x45, 0xd2, 0x53, 0x12, 0xf8, 0x45, 0x61, 0x91, 0x81, 0x85, 0x5f, 0x50, 0x74, 0x9b, 0xed, 0x52
		};
		
		const unsigned char expected[] = { 
			0xd9, 0x1b, 0xf9, 0xf3, 0x20, 0xf9, 0x3c, 0xa1, 0x79, 0xec, 0x3a, 0x74, 0xa4, 0xe3, 0x6e, 0xed, 
			0xd6, 0xd6, 0xca, 0xa9, 0x44, 0x61, 0x68, 0x5b, 0x36, 0xb6, 0x13, 0x6e, 0x8e, 0x6e, 0xa7, 0x00
		};
		
		try{
			OpenCL cipher( OpenCL::CPU, Block::Mode::CipherBlockChaining );
			
			const DataArray result = cipher.Decrypt( DataArray( data, data + 32 ), CBCRoundKey256, IVArray256 );
			
			const unsigned int size = result.size();
			for( unsigned int i = 0; i < size; i++ ){
				std::ostringstream stream;
				stream << "Element " << i << " Differs";
				
				CPPUNIT_ASSERT_EQUAL_MESSAGE( stream.str(), (int)expected[i], (int)result[i] );
			}
		}catch( DeviceUnavailiable& e ){
		
		}
	}
}
