#ifndef CRYPTOCL_TEST_AES_ROUNDKEY_H_
#define CRYPTOCL_TEST_AES_ROUNDKEY_H_

#include <cppunit/extensions/HelperMacros.h>

namespace AES {
	class RoundKeyTest : public CppUnit::TestFixture  {
		private:
			CPPUNIT_TEST_SUITE( RoundKeyTest );
				CPPUNIT_TEST( testBitSize128 );
				CPPUNIT_TEST( testRoundCount128 );
				CPPUNIT_TEST( testGenerate128 );
				CPPUNIT_TEST( testRoundNumber128 );
				CPPUNIT_TEST( testBitSize192 );
				CPPUNIT_TEST( testRoundCount192 );
				CPPUNIT_TEST( testGenerate192 );
				CPPUNIT_TEST( testRoundNumber192 );
				CPPUNIT_TEST( testBitSize256 );
				CPPUNIT_TEST( testRoundCount256 );
				CPPUNIT_TEST( testGenerate256 );
				CPPUNIT_TEST( testRoundNumber256 );
			CPPUNIT_TEST_SUITE_END();
		public:
			// 128 Bit Tests
			void testBitSize128();
			void testRoundCount128();
			void testGenerate128();
			void testRoundNumber128();
			
			// 192 Bit Tests
			void testBitSize192();
			void testRoundCount192();
			void testGenerate192();
			void testRoundNumber192();
			
			// 256 Bit Tests
			void testBitSize256();
			void testRoundCount256();
			void testGenerate256();
			void testRoundNumber256();
	};

}

#endif // CRYPTOCL_TEST_AES_ROUNDKEY_H_
