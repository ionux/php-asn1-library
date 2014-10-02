<?php
/**
 *  (c) 2014, Rich Morgan <rich.l.morgan@gmail.com>
 *
 *  Parses a PEM (base-64 encoded DER) file
 *
 *  This code is released under the MIT License (MIT).
 *  See the LICENSE file for the complete text or 
 *  notify me if you did not receive a copy with this
 *  file.
 */
 
 namespace ASN1;
 
 class Pem
 {
 
    /**
     * Identifier octet bit masks 
     *
     * The identifier octets encode the ASN.1 tag (class and number) of the type of
     * the data value. Its structure is defined as follows:
     *     -----------------------------------------------
     *    |  8  |  7  |  6  |  5  |  4  |  3  |  2  |  1  |
     *     -----------------------------------------------
     *    |   Class   | P/C |          Tag Number         |
     *     -----------------------------------------------
     *
     *     Octet Mask Name    Hex Value
     * ---------------------------------------------------------------------- */
    const  CLASS_BITMASK     = '0xC0'
    const  PC_BITMASK        = '0x20'
    const  TAGNUM_BITMASK    = '0x1F'

    
    /**
     * Class bits in a Type identifier octet
     *
     * Bit 8 and 7 of the identifier octet describe the class of the object.
     * Note that some of the ASN.1 types can be encoded using either primitive
     * or a constructed encoding at the option of the sender. The following
     * values are possible:
     *     Universal        - This type is native to ASN.1
     *     Application      - This type is only valid for one specific application
     *     Context-specific - The meaning of this type depends on the context
     *     Private          - This type is defined in a private specification
     *
     *     Class Name         Hex Value      Bit 8  Bit 7
     * ---------------------------------------------------------------------- */
    const  UNIVERSAL         = '0x00'    //   0      0 
    const  APPLICATION       = '0x40'    //   0      1
    const  CONTEXT           = '0x80'    //   1      0
    const  PRIVATE           = '0xC0'    //   1      1


    /**
     * Primitive/Constructed content type bits
     *
     * Bit 6 (P/C) states whether the content is primitive, like an INTEGER, or
     * constructed, which means it holds further TLV values, like a SET.
     *
     *     Content Type       Hex Value     Bit 6
     * ---------------------------------------------------------------------- */
    const  PRIMITIVE         = '0x00'    //   0
    const  CONSTRUCTED       = '0x20'    //   1


    /**
     * Universal Class Tags
     *
     * The remaining bits 5 to 1 contain the tag, which serves as the identifier
     * of the type of the content. The following tags are native to ASN.1:
     *
     *     Tag Name           Hex Value      P/C    Dec Value
     * ---------------------------------------------------------------------- */
    const  END_OF_CONTENT    = '0x00'    //   P         0 
    const  BOOLEAN           = '0x01'    //   P         1
    const  INTEGER           = '0x02'    //   P         2
    const  BIT_STRING        = '0x03'    //   P/C       3
    const  OCTET_STRING      = '0x04'    //   P/C       4 
    const  NULL              = '0x05'    //   P         5
    const  OBJ_IDENTIFIER    = '0x06'    //   P         6 
    const  OBJ_DESCRIPTOR    = '0x07'    //   P/C       7 
    const  EXTERNAL          = '0x08'    //   C         8 
    const  FLOAT             = '0x09'    //   P         9 
    const  ENUMERATED        = '0x0A'    //   P        10 
    const  EMBEDDED_PDV      = '0x0B'    //   C        11 
    const  UTF8_STRING       = '0x0C'    //   P/C      12
    const  RELATIVE_OID      = '0x0D'    //   P        13
    const  RESERVED_A        = '0x0E'    //   -        14
    const  RESERVED_B        = '0x0F'    //   -        15
    const  SEQUENCE          = '0x10'    //   C        16
    const  SET               = '0x11'    //   C        17
    const  NUMERIC_STRING    = '0x12'    //   P/C      18
    const  PRINTABLE_STRING  = '0x13'    //   P/C      19
    const  T61_STRING        = '0x14'    //   P/C      20
    const  VIDEOTEX_STRING   = '0x15'    //   P/C      21
    const  IA5_STRING        = '0x16'    //   P/C      22
    const  UTC_TIME          = '0x17'    //   P/C      23
    const  GENERALIZED_TIME  = '0x18'    //   P/C      24
    const  GRAPHIC_STRING    = '0x19'    //   P/C      25
    const  VISIBLE_STRING    = '0x1A'    //   P/C      26
    const  GENERAL_STRING    = '0x1B'    //   P/C      27
    const  UNIVERSAL_STRING  = '0x1C'    //   P/C      28
    const  CHARACTER_STRING  = '0x1D'    //   P/C      29
    const  BMPSTRING         = '0x1E'    //   P/C      30
    const  USE_LONG_FORM     = '0x1F'    //   -        31


    // Identifer tags greater than 30
    // See: http://en.wikipedia.org/wiki/X.690
    const  LEN_INDEF         = '0x80'    // Indefinite, or Long Form 
    const  LEN_SHORT         = '0x7F'    // Definite, or Short Form 


    public function __construct()
    {
        // TODO
    }
    
    /**
     * Decodes PEM data to retrieve the keypair.
     *
     * @param  string $pem_data The data to decode.
     * @return array            The keypair info.
     */
    private function pemDecode($pem_data)
    {
        $beg_ec_text = '-----BEGIN EC PRIVATE KEY-----';
        $end_ec_text = '-----END EC PRIVATE KEY-----';

        $decoded = '';

        $ecpemstruct = array();

        $pem_data = str_ireplace("\r", '', trim($pem_data));
        $pem_data = str_ireplace("\n", '', trim($pem_data));
        $pem_data = str_ireplace($beg_ec_text, '', $pem_data);
        $pem_data = str_ireplace($end_ec_text, '', $pem_data);

        $decoded = bin2hex(base64_decode($pem_data));

        if (strlen($decoded) < 230) {
            throw new \Exception('Invalid or corrupt secp256k1 key provided. Cannot decode the supplied PEM data.');
        }

        $ecpemstruct = array(
                             '*oct_sec_val'  => substr($decoded,14,64),
                             '*obj_id_val'   => substr($decoded,86,10),
                             '*bit_str_val'  => substr($decoded,106),
                       );

        if ($ecpemstruct['obj_id_val'] != '2b8104000a') {
            throw new \Exception('Invalid or corrupt secp256k1 key provided. Cannot decode the supplied PEM data.');
        }

        $private_key = $ecpemstruct['oct_sec_val'];
        $public_key  = $ecpemstruct['bit_str_val'];

        if (strlen($private_key) < 64 || strlen($public_key) < 128) {
            throw new \Exception('Invalid or corrupt secp256k1 key provided. Cannot decode the supplied PEM data.');
        }

        return array('private_key' => $private_key, 'public_key' => $public_key);
    }

    /**
     * Encodes keypair data to PEM format.
     *
     * @param  array  $keypair The keypair info.
     * @return string          The data to decode.
     */
    public function pemEncode($keypair)
    {
    	if (is_array($keypair) && (strlen($keypair[0]) < 64 || strlen($keypair[1]) < 128)) {
    		throw new \Exception('Invalid or corrupt secp256k1 keypair provided. Cannot decode the supplied PEM data.');
    	}

    	$beg_ec_text = '-----BEGIN EC PRIVATE KEY-----';
    	$end_ec_text = '-----END EC PRIVATE KEY-----';

    	$dec     = '';
    	$byte    = '';
    	$seq     = '';
    	$decoded = '';

    	$ecpemstruct = array();
    	$digits      = array();
    	$retval      = array();

    	for ($x = 0; $x < 256; $x++) {
    		$digits[$x] = chr($x);
    	}

    	$ecpemstruct = array(
    			'sequence_beg' => '30',
    			'total_len'    => '74',
    			'int_sec_beg'  => '02',
    			'int_sec_len'  => '01',
    			'int_sec_val'  => '01',
    			'oct_sec_beg'  => '04',
    			'oct_sec_len'  => '20',
    			'oct_sec_val'  => $keypair[0],
    			'a0_ele_beg'   => 'a0',
    			'a0_ele_len'   => '07',
    			'obj_id_beg'   => '06',
    			'obj_id_len'   => '05',
    			'obj_id_val'   => '2b8104000a',
    			'a1_ele_beg'   => 'a1',
    			'a1_ele_len'   => '44',
    			'bit_str_beg'  => '03',
    			'bit_str_len'  => '42',
    			'bit_str_val'  => '00' . $keypair[1],
    	);

    	echo "\r\n" . implode($ecpemstruct) . "\r\n";

    	$dec = trim(implode($ecpemstruct));

    	if (strlen($dec) < 230) {
    		throw new \Exception('Invalid or corrupt secp256k1 keypair provided. Cannot encode the supplied data.');
    	}

    	$dec = decodeHex('0x'.$dec);

    	echo "\r\n Decimal conversion is: $dec \r\n";

    	while (gmp_cmp($dec, '0') > 0) {
    		$dv = gmp_div($dec, '256');
    		$rem = gmp_strval(gmp_mod($dec, '256'));
    		$dec = $dv;
    		$byte = $byte.$digits[$rem];
    	}

    	$byte = $beg_ec_text . base64_encode(strrev($byte)) . $end_ec_text;
    	
        // TODO Add string breakup here.
        
        echo "\r\nThe data looks like: $byte \r\n";

    	return $byte;
    }
    
 }
