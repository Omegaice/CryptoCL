#ifndef CRYPTOCL_TEST_AES_OPENCL_H_
#define CRYPTOCL_TEST_AES_OPENCL_H_

#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class OpenCLTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( OpenCLTest );
				CPPUNIT_TEST( testEncryption128CPU );
				CPPUNIT_TEST( testEncryption128CPUMulti );
				CPPUNIT_TEST( testEncryptionCBC128CPU );
				CPPUNIT_TEST( testEncryptionCBC128CPUMulti );
				CPPUNIT_TEST( testDecryption128CPU );
				CPPUNIT_TEST( testDecryption128CPUMulti );
				CPPUNIT_TEST( testDecryptionCBC128CPU );
				CPPUNIT_TEST( testDecryptionCBC128CPUMulti );
				CPPUNIT_TEST( testEncryption128GPU );
				CPPUNIT_TEST( testEncryption128GPUMulti );
				CPPUNIT_TEST( testEncryptionCBC128GPU );
				CPPUNIT_TEST( testEncryptionCBC128GPUMulti );
				CPPUNIT_TEST( testDecryption128GPU );
				CPPUNIT_TEST( testDecryption128GPUMulti );
				CPPUNIT_TEST( testDecryptionCBC128GPU );
				CPPUNIT_TEST( testDecryptionCBC128GPUMulti );
				CPPUNIT_TEST( testEncryption192CPU );
				CPPUNIT_TEST( testEncryption192CPUMulti );
				CPPUNIT_TEST( testEncryptionCBC192CPU );
				CPPUNIT_TEST( testEncryptionCBC192CPUMulti );
				CPPUNIT_TEST( testDecryption192CPU );
				CPPUNIT_TEST( testDecryption192CPUMulti );
				CPPUNIT_TEST( testDecryptionCBC192CPU );
				CPPUNIT_TEST( testDecryptionCBC192CPUMulti );
				CPPUNIT_TEST( testEncryption192GPU );
				CPPUNIT_TEST( testEncryption192GPUMulti );
				CPPUNIT_TEST( testEncryptionCBC192GPU );
				CPPUNIT_TEST( testEncryptionCBC192GPUMulti );
				CPPUNIT_TEST( testDecryption192GPU );
				CPPUNIT_TEST( testDecryption192GPUMulti );
				CPPUNIT_TEST( testDecryptionCBC192GPU );
				CPPUNIT_TEST( testDecryptionCBC192GPUMulti );
				CPPUNIT_TEST( testEncryption256CPU );
				CPPUNIT_TEST( testEncryption256CPUMulti );
				CPPUNIT_TEST( testEncryptionCBC256CPU );
				CPPUNIT_TEST( testEncryptionCBC256CPUMulti );
				CPPUNIT_TEST( testDecryption256CPU );
				CPPUNIT_TEST( testDecryption256CPUMulti );
				CPPUNIT_TEST( testDecryptionCBC256CPU );
				CPPUNIT_TEST( testDecryptionCBC256CPUMulti );
				CPPUNIT_TEST( testEncryption256GPU );
				CPPUNIT_TEST( testEncryption256GPUMulti );
				CPPUNIT_TEST( testEncryptionCBC256GPU );
				CPPUNIT_TEST( testEncryptionCBC256GPUMulti );
				CPPUNIT_TEST( testDecryption256GPU );
				CPPUNIT_TEST( testDecryption256GPUMulti );
				CPPUNIT_TEST( testDecryptionCBC256GPU );
				CPPUNIT_TEST( testDecryptionCBC256GPUMulti );
			CPPUNIT_TEST_SUITE_END();
		public:
			// 128 Bit Tests
			void testEncryption128CPU();
			void testEncryption128CPUMulti();
			void testEncryptionCBC128CPU();
			void testEncryptionCBC128CPUMulti();
			void testDecryption128CPU();
			void testDecryption128CPUMulti();
			void testDecryptionCBC128CPU();
			void testDecryptionCBC128CPUMulti();
			
			void testEncryption128GPU();
			void testEncryption128GPUMulti();
			void testEncryptionCBC128GPU();
			void testEncryptionCBC128GPUMulti();
			void testDecryption128GPU();
			void testDecryption128GPUMulti();
			void testDecryptionCBC128GPU();
			void testDecryptionCBC128GPUMulti();
			
			// 192 Bit Tests
			void testEncryption192CPU();
			void testEncryption192CPUMulti();
			void testEncryptionCBC192CPU();
			void testEncryptionCBC192CPUMulti();
			void testDecryption192CPU();
			void testDecryption192CPUMulti();
			void testDecryptionCBC192CPU();
			void testDecryptionCBC192CPUMulti();
			
			void testEncryption192GPU();
			void testEncryption192GPUMulti();
			void testEncryptionCBC192GPU();
			void testEncryptionCBC192GPUMulti();
			void testDecryption192GPU();
			void testDecryption192GPUMulti();
			void testDecryptionCBC192GPU();
			void testDecryptionCBC192GPUMulti();
			
			// 256 Bit Tests
			void testEncryption256CPU();
			void testEncryption256CPUMulti();
			void testEncryptionCBC256CPU();
			void testEncryptionCBC256CPUMulti();
			void testDecryption256CPU();
			void testDecryption256CPUMulti();
			void testDecryptionCBC256CPU();
			void testDecryptionCBC256CPUMulti();
			
			void testEncryption256GPU();
			void testEncryption256GPUMulti();
			void testEncryptionCBC256GPU();
			void testEncryptionCBC256GPUMulti();
			void testDecryption256GPU();
			void testDecryption256GPUMulti();
			void testDecryptionCBC256GPU();
			void testDecryptionCBC256GPUMulti();
	};

}

#endif // CRYPTOCL_TEST_AES_OPENCL_H_
