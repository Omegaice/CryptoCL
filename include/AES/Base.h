#ifndef AES_BASE_H_
#define AES_BASE_H_

#include <vector>

namespace AES {
	typedef std::vector<unsigned char> CharArray;
	
	class Base {
		protected:
			CharArray mRoundKey;
			static unsigned char Rcon[255], SBox[256], InvSBox[256];
		public:
			Base();
			virtual ~Base();
			
			virtual void Initialise( const CharArray& key );
		protected:
			const CharArray Rotate( const CharArray& input );
			const CharArray KeyScheduleCore( const CharArray& input, const unsigned int iteration );
	};
}

#endif // AES_BASE_H_
