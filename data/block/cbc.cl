#define BlockSize 16

__kernel void CipherBlockChain( __global uchar *block, const uint blockOffset,
	__global const uchar *value, const uint valOffset ) {

	for( unsigned int i = 0; i < BlockSize; i++ ){
		block[blockOffset*BlockSize+i] = block[blockOffset*BlockSize+i] ^ value[valOffset*BlockSize+i];
	}
}