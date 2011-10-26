#ifndef AES_REFERENCE_H_
#define AES_REFERENCE_H_

#include "AES/Base.h"

namespace AES {
	class Reference : public Base {
		protected:	
			CharArray mState;
		public:
			const CharArray Encrypt( const CharArray& data );
			const CharArray Decrypt( const CharArray& data );
		protected:
			void AddRoundKey( const unsigned int round );
			
			/* Encryption Helpers */
			void SubBytes();
			void ShiftRows();
			void MixColumns();
			
			/* Decryption Helpers */
			void InvSubBytes();
			void InvShiftRows();
			void InvMixColumns();
	};
}

#endif // AES_REFERENCE_H_
