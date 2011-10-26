#ifndef CRYPTOCL_TEST_AES_OPENCL_H_
#define CRYPTOCL_TEST_AES_OPENCL_H_

#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class OpenCLTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( OpenCLTest );
				CPPUNIT_TEST( testEncryption128 );
				CPPUNIT_TEST( testDecryption128 );
				CPPUNIT_TEST( testEncryption192 );
				CPPUNIT_TEST( testDecryption192 );
				CPPUNIT_TEST( testEncryption256 );
				CPPUNIT_TEST( testDecryption256 );
			CPPUNIT_TEST_SUITE_END();
		public:
			// 128 Bit Tests
			void testEncryption128();
			void testDecryption128();
			
			// 192 Bit Tests
			void testEncryption192();
			void testDecryption192();
			
			// 256 Bit Tests
			void testEncryption256();
			void testDecryption256();
	};

}

#endif // CRYPTOCL_TEST_AES_OPENCL_H_
