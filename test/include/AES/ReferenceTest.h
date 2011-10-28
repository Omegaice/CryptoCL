#ifndef CRYPTOCL_TEST_AES_REFERENCE_H_
#define CRYPTOCL_TEST_AES_REFERENCE_H_

#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class ReferenceTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( ReferenceTest );
				CPPUNIT_TEST( testEncryption128 );
				CPPUNIT_TEST( testEncryptionCBC128 );
				CPPUNIT_TEST( testDecryption128 );
				CPPUNIT_TEST( testDecryptionCBC128 );
				CPPUNIT_TEST( testEncryption192 );
				CPPUNIT_TEST( testEncryptionCBC192 );
				CPPUNIT_TEST( testDecryption192 );
				CPPUNIT_TEST( testDecryptionCBC192 );
				CPPUNIT_TEST( testEncryption256 );
				CPPUNIT_TEST( testEncryptionCBC256 );
				CPPUNIT_TEST( testDecryption256 );
				CPPUNIT_TEST( testDecryptionCBC256 );
			CPPUNIT_TEST_SUITE_END();
		public:
			// 128 Bit Tests
			void testEncryption128();
			void testEncryptionCBC128();
			
			void testDecryption128();
			void testDecryptionCBC128();
			
			// 192 Bit Tests
			void testEncryption192();
			void testEncryptionCBC192();
			
			void testDecryption192();
			void testDecryptionCBC192();
			
			// 256 Bit Tests
			void testEncryption256();
			void testEncryptionCBC256();
			
			void testDecryption256();
			void testDecryptionCBC256();
	};

}

#endif // CRYPTOCL_TEST_AES_REFERENCE_H_
