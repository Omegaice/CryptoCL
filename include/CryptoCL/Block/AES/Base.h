#ifndef CRYPTOCL_AES_BASE_H_
#define CRYPTOCL_AES_BASE_H_

#include "CryptoCL/Cipher.h"
#include "CryptoCL/Block/AES/RoundKey.h"

namespace CryptoCL {
	namespace Block {
		namespace AES {
			class Base : public Cipher {
				protected:
					RoundKey mKey;
					bool mInitialised;
				public:
					Base();
					virtual ~Base();
				
					void Initialise( const RoundKey& key );
					bool isInitialised() const;
				protected:
					virtual void OnInitialise( const RoundKey& key );
				public:
					static unsigned char Rcon[255], SBox[256], InvSBox[256];
			};
		}
	}
}

#endif // CRYPTOCL_AES_BASE_H_
