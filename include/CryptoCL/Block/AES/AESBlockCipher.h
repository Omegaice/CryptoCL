#ifndef CRYPTOCL_AES_AESBLOCKCIPHER_H_
#define CRYPTOCL_AES_AESBLOCKCIPHER_H_

#include "CryptoCL/Block/BlockCipher.h"
#include "CryptoCL/Block/AES/RoundKey.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			class AESBlockCipher : public BlockCipher {
				public:
					AESBlockCipher( const Mode::BlockMode mode = Mode::ElectronicCookBook );
					virtual ~AESBlockCipher();
				public:
					static unsigned char Rcon[255], SBox[256], InvSBox[256];
			};
		}
	}
}

#endif // CRYPTOCL_AES_AESBLOCKCIPHER_H_
