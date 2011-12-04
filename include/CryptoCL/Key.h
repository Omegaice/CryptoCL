#ifndef CRYPTOCL_KEY_H_
#define CRYPTOCL_KEY_H_

#include <vector>

namespace CryptoCL {
	typedef std::vector<unsigned char> DataArray;
	
	class Key {
		protected:
			const DataArray mKey;
		public:
			Key( const Key& other );
			Key( const DataArray& key );
			virtual ~Key();
			
			const DataArray& Data() const;
		private:
			Key& operator=( const Key& other );
	};	
}

#endif // CRYPTOCL_KEY_H_
