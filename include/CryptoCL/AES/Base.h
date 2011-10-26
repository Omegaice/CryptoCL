#ifndef CRYPTOCL_AES_BASE_H_
#define CRYPTOCL_AES_BASE_H_

#include <vector>

namespace CryptoCL {
	namespace AES {
		typedef std::vector<unsigned char> DataArray;
		
		extern unsigned char Rcon[255], SBox[256], InvSBox[256];
	}
}

#endif // CRYPTOCL_AES_BASE_H_
