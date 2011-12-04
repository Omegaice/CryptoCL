#ifndef CRYPTOCL_TEST_AES_REFERENCE_H_
#define CRYPTOCL_TEST_AES_REFERENCE_H_

#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class ReferenceTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( ReferenceTest );
				CPPUNIT_TEST( testEncryption128 );
				CPPUNIT_TEST( testEncryption128Multi );
				CPPUNIT_TEST( testEncryptionCBC128 );
				CPPUNIT_TEST( testEncryptionCBC128Multi );
				CPPUNIT_TEST( testDecryption128 );
				CPPUNIT_TEST( testDecryption128Multi );
				CPPUNIT_TEST( testDecryptionCBC128 );
				CPPUNIT_TEST( testDecryptionCBC128Multi );
				CPPUNIT_TEST( testEncryption192 );
				CPPUNIT_TEST( testEncryption192Multi );
				CPPUNIT_TEST( testEncryptionCBC192 );
				CPPUNIT_TEST( testEncryptionCBC192Multi );
				CPPUNIT_TEST( testDecryption192 );
				CPPUNIT_TEST( testDecryption192Multi );
				CPPUNIT_TEST( testDecryptionCBC192 );
				CPPUNIT_TEST( testDecryptionCBC192Multi );
				CPPUNIT_TEST( testEncryption256 );
				CPPUNIT_TEST( testEncryption256Multi );
				CPPUNIT_TEST( testEncryptionCBC256 );
				CPPUNIT_TEST( testEncryptionCBC256Multi );
				CPPUNIT_TEST( testDecryption256 );
				CPPUNIT_TEST( testDecryption256Multi );
				CPPUNIT_TEST( testDecryptionCBC256 );
				CPPUNIT_TEST( testDecryptionCBC256Multi );
			CPPUNIT_TEST_SUITE_END();
		public:
			// 128 Bit Tests
			void testEncryption128();
			void testEncryption128Multi();
			void testEncryptionCBC128();
			void testEncryptionCBC128Multi();
			
			void testDecryption128();
			void testDecryption128Multi();
			void testDecryptionCBC128();
			void testDecryptionCBC128Multi();
			
			// 192 Bit Tests
			void testEncryption192();
			void testEncryption192Multi();
			void testEncryptionCBC192();
			void testEncryptionCBC192Multi();
			
			void testDecryption192();
			void testDecryption192Multi();
			void testDecryptionCBC192();
			void testDecryptionCBC192Multi();
			
			// 256 Bit Tests
			void testEncryption256();
			void testEncryption256Multi();
			void testEncryptionCBC256();
			void testEncryptionCBC256Multi();
			
			void testDecryption256();
			void testDecryption256Multi();
			void testDecryptionCBC256();
			void testDecryptionCBC256Multi();
	};

}

#endif // CRYPTOCL_TEST_AES_REFERENCE_H_
