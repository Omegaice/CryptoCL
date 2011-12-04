#include "CryptoCL/Key.h"

namespace CryptoCL {
	Key::Key( const DataArray& key ) : mKey( key ) {
	
	}
	
	Key::Key( const Key& other ) : mKey( other.mKey ){
	
	}
	
	Key::~Key() {
	
	}
	
	const DataArray& Key::Data() const{
		return mKey;
	}
	
	Key& Key::operator=( const Key& other ) {
		return *this;
	}
}
