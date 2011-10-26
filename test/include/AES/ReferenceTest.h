#ifndef CRYPTOCL_TEST_AES_REFERENCE_H_
#define CRYPTOCL_TEST_AES_REFERENCE_H_

#include <AES/Reference.h>
#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class ReferenceTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( ReferenceTest );
				CPPUNIT_TEST( testRoundKeyGeneration );
				CPPUNIT_TEST( testEncryption );
				CPPUNIT_TEST( testDecryption );
			CPPUNIT_TEST_SUITE_END();
		public:
			void testRoundKeyGeneration();
			void testEncryption();
			void testDecryption();
	};

}

#endif // CRYPTOCL_TEST_AES_REFERENCE_H_
