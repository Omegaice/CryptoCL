#ifndef CRYPTOCL_TEST_AES_OPENCL_H_
#define CRYPTOCL_TEST_AES_OPENCL_H_

#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class OpenCLTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( OpenCLTest );
				CPPUNIT_TEST( testEncryption128CPU );
				CPPUNIT_TEST( testEncryptionCBC128CPU );
				CPPUNIT_TEST( testDecryption128CPU );
				CPPUNIT_TEST( testDecryptionCBC128CPU );
				CPPUNIT_TEST( testEncryption128GPU );
				CPPUNIT_TEST( testEncryptionCBC128GPU );
				CPPUNIT_TEST( testDecryption128GPU );
				CPPUNIT_TEST( testDecryptionCBC128GPU );
				CPPUNIT_TEST( testEncryption192CPU );
				CPPUNIT_TEST( testEncryptionCBC192CPU );
				CPPUNIT_TEST( testDecryption192CPU );
				CPPUNIT_TEST( testDecryptionCBC192CPU );
				CPPUNIT_TEST( testEncryption192GPU );
				CPPUNIT_TEST( testEncryptionCBC192GPU );
				CPPUNIT_TEST( testDecryption192GPU );
				CPPUNIT_TEST( testDecryptionCBC192GPU );
				CPPUNIT_TEST( testEncryption256CPU );
				CPPUNIT_TEST( testEncryptionCBC256CPU );
				CPPUNIT_TEST( testDecryption256CPU );
				CPPUNIT_TEST( testDecryptionCBC256CPU );
				CPPUNIT_TEST( testEncryption256GPU );
				CPPUNIT_TEST( testEncryptionCBC256GPU );
				CPPUNIT_TEST( testDecryption256GPU );
				CPPUNIT_TEST( testDecryptionCBC256GPU );
			CPPUNIT_TEST_SUITE_END();
		public:
			// 128 Bit Tests
			void testEncryption128CPU();
			void testEncryptionCBC128CPU();
			void testDecryption128CPU();
			void testDecryptionCBC128CPU();
			
			void testEncryption128GPU();
			void testEncryptionCBC128GPU();
			void testDecryption128GPU();
			void testDecryptionCBC128GPU();
			
			// 192 Bit Tests
			void testEncryption192CPU();
			void testEncryptionCBC192CPU();
			void testDecryption192CPU();
			void testDecryptionCBC192CPU();
			
			void testEncryption192GPU();
			void testEncryptionCBC192GPU();
			void testDecryption192GPU();
			void testDecryptionCBC192GPU();
			
			// 256 Bit Tests
			void testEncryption256CPU();
			void testEncryptionCBC256CPU();
			void testDecryption256CPU();
			void testDecryptionCBC256CPU();
			
			void testEncryption256GPU();
			void testEncryptionCBC256GPU();
			void testDecryption256GPU();
			void testDecryptionCBC256GPU();
	};

}

#endif // CRYPTOCL_TEST_AES_OPENCL_H_
