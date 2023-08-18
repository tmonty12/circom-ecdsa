pragma circom 2.0.2;

include "./ecdsa.circom";
include "./circuits/bigint.circom";
include "./circuits/vocdoni-keccak/keccak.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

template Is21orOlder(nBeforeBits, nAddressBits, nBetweenBits, nBirthdateBits, nAfterBits, nBits) {
    // Partitionining the verifiable credential message bit stream 
    signal input before[nBeforeBits];
    signal input address[nAddressBits];
    signal input between[nBetweenBits];
    signal input birthdate[nBirthdateBits];
    signal input after[nAfterBits];

    // year21 - year of a just turned 21 year old (current year - 21)
    // month21 - month of a just turned 21 year old (current month)
    // day21 - day of a just turned 21 year old (current day)
    signal input year21;
    signal input month21;
    signal input day21;

    // r - r component of verifiable credential signature encoded a bigint tuple
    // s - s component of verifiable credential signature encoded as bigint tuple
    signal input r[4];
    signal input s[4];

    // pubkey - public key of verifiable credential issuer, encoded as the (x,y) coordinate as a bigint tuple
    signal input pubkey[2][4];

    // Intermediate signals 
    signal year;
    signal month;
    signal day;
    signal dayComparisonIntermediate;
    signal dayComparison;
    signal msgHashValue[32][4];
    signal msgHash;

    // 1 - verifiable credential holder is 21 or older
    // 0 - verifiable credential holder is less than 21 years old
    signal output is21OrOlder;

    // nBits - total number of bits in the verifiable credential message
    // constrain nBits to be equal to the sum of the bit partitions
    nBits === nBeforeBits + nAddressBits + nBetweenBits + nBirthdateBits + nAfterBits;

    // keccak component used for constraining verifiable credential message
    // being equal to the hash output used for generating the vc signature
    component keccak = Keccak(nBits, 32*8);

    // constraining the input of the keccak hash to be the bits stored in each parition
    for(var i = 0; i < nBeforeBits; i++){
        keccak.in[i] <== before[i];
    }
    for(var i = 0; i < nAddressBits; i++){
        keccak.in[nBeforeBits+i] <== address[i];
    }
    for(var i = 0; i < nBetweenBits; i++){
        keccak.in[nBeforeBits+nAddressBits+i] <== between[i];
    }
    for(var i = 0; i < nBirthdateBits; i++){
        keccak.in[nBeforeBits+nAddressBits+nBetweenBits+i] <== birthdate[i];
    }
    for(var i = 0; i < nAfterBits; i++){
        keccak.in[nBeforeBits+nAddressBits+nBetweenBits+nBirthdateBits+i] <== after[i];
    }

    // creating an array of Bits2Num components
    // to convert the address input bits into each byte value in decimal
    component addressNums[nAddressBits/8];
    for(var i=0; i < (nAddressBits/8); i++){
        addressNums[i] = Bits2Num(8);
    }

    // Need to partition the address bits by every 8 bits because
    // the address bits are encoded in little endian format (msb is first)
    for(var i=0; i < (nAddressBits/8); i++){
        for(var j=0; j < 8; j++){
            addressNums[i].in[j] <== address[(i*8)+j];
           
        }
        log(addressNums[i].out);
    }

    // creating an array of Bits2Num components
    // to convert the birthdate input bits into each byte value in decimal
    component birthdateNums[nBirthdateBits/8];
    for(var i=0; i < (nBirthdateBits/8); i++){
        birthdateNums[i] = Bits2Num(8);
    }
    for(var i=0; i < (nBirthdateBits/8); i++){
        for(var j=0; j < 8; j++){
            birthdateNums[i].in[j] <== birthdate[(i*8)+j];
        }
    }

    // VC message values encoded in utf-8. To convert from utf-8 encoding to number value, you can just subtract 48.
    year <== (birthdateNums[0].out-48)*1000 + (birthdateNums[1].out-48)*100 + (birthdateNums[2].out-48)*10 + (birthdateNums[3].out-48);
    month <== (birthdateNums[5].out-48)*10 + (birthdateNums[6].out-48);
    day <== (birthdateNums[8].out-48)*10 + (birthdateNums[9].out-48);

    // comparing the VC year to the current 21 year old year.
    // if VC year < current 21 year old year, we know the holder is 21 years or older.
    // else, we need to to check if the years are equal and how the month and day values compare.
    component yearLessThan = LessThan(64);
    yearLessThan.in[0] <== year;
    yearLessThan.in[1] <== year21;

    // if the VC year is equal to the current 21 year old year and the VC month is less
    // than the 21 year old month, than the holder is 21 years old.
    // else, we need to check if the years and months are equal and how the day values compare.
    component yearEqual = IsEqual();
    yearEqual.in[0] <== year;
    yearEqual.in[1] <== year21;
    component monthLessThan = LessThan(64);
    monthLessThan.in[0] <== month;
    monthLessThan.in[1] <== month21;

    // if the VC year is equal to the current 21 year old year, the VC month is equal to the current 21 year
    // old month and the VC day is less than of equal to the current 21 year old day, we know the holder
    // is 21 years old.
    // else, the holder is not 21 years old.
    component monthEqual = IsEqual();
    monthEqual.in[0] <== month;
    monthEqual.in[1] <== month21;
    component dayLessEqThan = LessEqThan(64);
    dayLessEqThan.in[0] <== day;
    dayLessEqThan.in[1] <== day21;

    // needed intermediate signals to achieve quadratic form
    dayComparisonIntermediate <==  yearEqual.out*monthEqual.out;
    dayComparison <== dayComparisonIntermediate*dayLessEqThan.out;

    // if one of the cases above is true, than is21orOlder will be constrained to 1.
    // else, the is21orOlder will be constrained to 0.
    is21OrOlder <== yearLessThan.out + yearEqual.out*monthLessThan.out + dayComparison;

    // msgHashBytes - array of  Bits2Num components for calculating the decimal value of
    // each byte in the msgHash
    // mult - array of BigMult components for doing big int multiplication.
    // add - array of BigAdd components for doing big int addition.
    // *Needed to use circuits for big int arithmetic because hash value in big int is greater
    // than the prime field. It also stores the msgHash value in the big int tuple format needed for the verify component
    component msgHashBytes[32];
    component mult[32];
    component add[32];
    for (var i = 0; i < 32; i++){
        msgHashBytes[i] = Bits2Num(8);
        mult[i] = BigMult(64, 4);
        add[i] = BigAdd(64, 4);
        for (var j = 0; j < 8; j++){
            msgHashBytes[i].in[j] <== keccak.out[(i*8)+j];
        }

        
        // Calculate the msgHashValue in decimal from the msgHashBytes
        // Conversion is done by multiplying the previous value up to the last byte by 256 and adding the current byte value.
        if (i == 0){
            mult[i].a[0] <== 0;
            mult[i].a[1] <== 0;
            mult[i].a[2] <== 0;
            mult[i].a[3] <== 0;
        } else {
            mult[i].a[0] <== msgHashValue[i-1][0];
            mult[i].a[1] <== msgHashValue[i-1][1];
            mult[i].a[2] <== msgHashValue[i-1][2];
            mult[i].a[3] <== msgHashValue[i-1][3];
        }
        
        mult[i].b[0] <== 256;
        mult[i].b[1] <== 0; 
        mult[i].b[2] <== 0; 
        mult[i].b[3] <== 0; 

        add[i].a[0] <== mult[i].out[0];
        add[i].a[1] <== mult[i].out[1];
        add[i].a[2] <== mult[i].out[2];
        add[i].a[3] <== mult[i].out[3];
        add[i].b[0] <== msgHashBytes[i].out;
        add[i].b[1] <== 0;
        add[i].b[2] <== 0;
        add[i].b[3] <== 0;

        msgHashValue[i][0] <== add[i].out[0];
        msgHashValue[i][1] <== add[i].out[1];
        msgHashValue[i][2] <== add[i].out[2];
        msgHashValue[i][3] <== add[i].out[3];
    }

    // component from verifying the verifiable credential signature
    // msghash provided by the keccak hash and format conversion done above.
    // r, s and pubkey value provided by user input
    component verifySignature = ECDSAVerifyNoPubkeyCheck(64,4);
    verifySignature.msghash[0] <== msgHashValue[31][0];
    verifySignature.msghash[1] <== msgHashValue[31][1];
    verifySignature.msghash[2] <== msgHashValue[31][2];
    verifySignature.msghash[3] <== msgHashValue[31][3];
    verifySignature.r[0] <== r[0];
    verifySignature.r[1] <== r[1];
    verifySignature.r[2] <== r[2];
    verifySignature.r[3] <== r[3];
    verifySignature.s[0] <== s[0];
    verifySignature.s[1] <== s[1];
    verifySignature.s[2] <== s[2];
    verifySignature.s[3] <== s[3];
    verifySignature.pubkey[0][0] <== pubkey[0][0];
    verifySignature.pubkey[0][1] <== pubkey[0][1];
    verifySignature.pubkey[0][2] <== pubkey[0][2];
    verifySignature.pubkey[0][3] <== pubkey[0][3];
    verifySignature.pubkey[1][0] <== pubkey[1][0];
    verifySignature.pubkey[1][1] <== pubkey[1][1];
    verifySignature.pubkey[1][2] <== pubkey[1][2];
    verifySignature.pubkey[1][3] <== pubkey[1][3];

    // constrain the signature result to be 1 (valid signature)
    verifySignature.result === 1;
}


component main {public [year21, month21, day21, pubkey]} = Is21orOlder(46*8, 40*8, 16*8, 10*8, 2*8, (46+40+16+10+2)*8);
