#ifndef CRYPTOCL_TEST_AES_REFERENCE_H_
#define CRYPTOCL_TEST_AES_REFERENCE_H_

#include <AES/Reference.h>
#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class ReferenceTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( ReferenceTest );
				CPPUNIT_TEST( testRoundKeyGeneration );
				CPPUNIT_TEST( testEncryption128 );
				CPPUNIT_TEST( testEncryption192 );
				CPPUNIT_TEST( testEncryption256 );
				CPPUNIT_TEST( testDecryption128 );
				CPPUNIT_TEST( testDecryption192 );
				CPPUNIT_TEST( testDecryption256 );
			CPPUNIT_TEST_SUITE_END();
		public:
			void testRoundKeyGeneration();
			void testEncryption128();
			void testEncryption192();
			void testEncryption256();
			void testDecryption128();
			void testDecryption192();
			void testDecryption256();
	};

}

#endif // CRYPTOCL_TEST_AES_REFERENCE_H_
