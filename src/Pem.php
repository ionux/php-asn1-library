<?php
/******************************************************************************
 * This file is part of the PHP ASN.1 Library project. You can always find the
 * latest version of this class and project at: https://github.com/ionux/php-asn1-library
 *
 * Copyright (c) 2014-2023 Rich Morgan, rich@richmorgan.me
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ******************************************************************************/

namespace ASN1;

/**
 * Parses, decodes and encodes a PEM (base-64 encoded DER) file or data string.
 *
 * @author Rich Morgan <rich@richmorgan.me>
 */
final class Pem
{
    use \Phactor\Math;

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
    const  CLASS_BITMASK     = '0xC0';
    const  PC_BITMASK        = '0x20';
    const  TAGNUM_BITMASK    = '0x1F';
    
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
     *     Class Name            Hex Value      Bit 8  Bit 7
     * ---------------------------------------------------------------------- */
    const  UNIVERSAL_CB         = '0x00';    //   0      0 
    const  APPLICATION_CB       = '0x40';    //   0      1
    const  CONTEXT_CB           = '0x80';    //   1      0
    const  PRIVATE_SPEC_CB      = '0xC0';    //   1      1

    /**
     * Primitive/Constructed content type bits
     *
     * Bit 6 (P/C) states whether the content is primitive, like an INTEGER, or
     * constructed, which means it holds further TLV values, like a SET.
     *
     *     Content Type          Hex Value     Bit 6
     * ---------------------------------------------------------------------- */
    const  PRIMITIVE_CT         = '0x00';    //   0
    const  CONSTRUCTED_CT       = '0x20';    //   1

    /**
     * Universal Class Tags
     *
     * The remaining bits 5 to 1 contain the tag, which serves as the identifier
     * of the type of the content. The following tags are native to ASN.1:
     *
     *     Tag Name               Hex Value      P/C    Dec Value
     * ---------------------------------------------------------------------- */
    const  END_OF_CONTENT_TAG    = '0x00';    //  P         0 
    const  BOOLEAN_TAG           = '0x01';    //  P         1
    const  INTEGER_TAG           = '0x02';    //  P         2
    const  BIT_STRING_TAG        = '0x03';    //  P/C       3
    const  OCTET_STRING_TAG      = '0x04';    //  P/C       4 
    const  NULL_TAG              = '0x05';    //  P         5
    const  OBJ_IDENTIFIER_TAG    = '0x06';    //  P         6 
    const  OBJ_DESCRIPTOR_TAG    = '0x07';    //  P/C       7 
    const  EXTERNAL_TAG          = '0x08';    //  C         8 
    const  FLOAT_TAG             = '0x09';    //  P         9 
    const  ENUMERATED_TAG        = '0x0A';    //  P        10 
    const  EMBEDDED_PDV_TAG      = '0x0B';    //  C        11 
    const  UTF8_STRING_TAG       = '0x0C';    //  P/C      12
    const  RELATIVE_OID_TAG      = '0x0D';    //  P        13
    const  RESERVED_A_TAG        = '0x0E';    //  -        14
    const  RESERVED_B_TAG        = '0x0F';    //  -        15
    const  SEQUENCE_TAG          = '0x10';    //  C        16
    const  SET_TAG               = '0x11';    //  C        17
    const  NUMERIC_STRING_TAG    = '0x12';    //  P/C      18
    const  PRINTABLE_STRING_TAG  = '0x13';    //  P/C      19
    const  T61_STRING_TAG        = '0x14';    //  P/C      20
    const  VIDEOTEX_STRING_TAG   = '0x15';    //  P/C      21
    const  IA5_STRING_TAG        = '0x16';    //  P/C      22
    const  UTC_TIME_TAG          = '0x17';    //  P/C      23
    const  GENERALIZED_TIME_TAG  = '0x18';    //  P/C      24
    const  GRAPHIC_STRING_TAG    = '0x19';    //  P/C      25
    const  VISIBLE_STRING_TAG    = '0x1A';    //  P/C      26
    const  GENERAL_STRING_TAG    = '0x1B';    //  P/C      27
    const  UNIVERSAL_STRING_TAG  = '0x1C';    //  P/C      28
    const  CHARACTER_STRING_TAG  = '0x1D';    //  P/C      29
    const  BMPSTRING_TAG         = '0x1E';    //  P/C      30
    const  USE_LONG_FORM_TAG     = '0x1F';    //  -        31

    /**
     * Identifer tags greater than 30
     *
     * See: http://en.wikipedia.org/wiki/X.690
     * ---------------------------------------------------------------------- */
    const  LEN_INDEF_TAG         = '0x80';    // Indefinite, or Long Form 
    const  LEN_SHORT_TAG         = '0x7F';    // Definite, or Short Form 

    /**
     * Public constructor method.
     */
    public function __construct()
    {
        $this->checkExtensions();
    }
    
    /**
     * Decodes PEM data to retrieve the keypair.
     *
     * @param  string $pem_data The data to decode.
     * @return array            The keypair info.
     * @throws \Exception
     */
    public function pemDecode($pem_data = null)
    {
        if (empty($pem_data)) {
            throw new \Exception('[ERROR] In Pem::pemDecode(): Empty or null key data provided to method.');
        }

        // Public Key (PKCS#8) Tags:
        $beg_pk_pub_text = '-----BEGIN PUBLIC KEY-----';
        $end_pk_pub_text = '-----END PUBLIC KEY-----';

        /**
         * Public Key (PKCS#8) DER Structure:
         *
         * PublicKeyInfo ::= SEQUENCE {
         *     algorithm       AlgorithmIdentifier,
         *     PublicKey       BIT STRING
         * }
         *
         * AlgorithmIdentifier ::= SEQUENCE {
         *     algorithm       OBJECT IDENTIFIER,
         *     parameters      ANY DEFINED BY algorithm OPTIONAL
         * }
         */

        // Private Key (PKCS#8) Tags:
        $beg_pk_pri_text = '-----BEGIN PRIVATE KEY-----';
        $end_pk_pri_text = '-----END PRIVATE KEY-----';

        /**
         * Private Key (PKCS#8) DER Structure:
         *
         * PrivateKeyInfo ::= SEQUENCE {
         *     version         Version,
         *     algorithm       AlgorithmIdentifier,
         *     PrivateKey      BIT STRING
         * }
         *
         * AlgorithmIdentifier ::= SEQUENCE {
         *     algorithm       OBJECT IDENTIFIER,
         *     parameters      ANY DEFINED BY algorithm OPTIONAL
         * }
         */

        // RSA Public Key (PKCS#1) Tags:
        $beg_rsa_pub_text = '-----BEGIN RSA PUBLIC KEY-----';
        $end_rsa_pub_text = '-----END RSA PUBLIC KEY-----';

        /**
         * RSA Public Key (PKCS#1) DER Structure
         *
         * RSAPublicKey ::= SEQUENCE {
         *     modulus           INTEGER,  -- n
         *     publicExponent    INTEGER   -- e
         * }
         *
         * RSA public key, the OID is 1.2.840.113549.1.1.1 &
         * RSAPublicKey representing the PublicKey key data
         * bitstring is present.
         */

        // RSA Private Key (PKCS#1) Tags:
        $beg_rsa_pri_text = '-----BEGIN RSA PRIVATE KEY-----';
        $end_rsa_pri_text = '-----END RSA PRIVATE KEY-----';

        /**
         * RSA Private Key (PKCS#1) DER Structure
         *
         * RSAPrivateKey ::= SEQUENCE {
         *     version           Version,
         *     modulus           INTEGER,  -- n
         *     publicExponent    INTEGER,  -- e
         *     privateExponent   INTEGER,  -- d
         *     prime1            INTEGER,  -- p
         *     prime2            INTEGER,  -- q
         *     exponent1         INTEGER,  -- d mod (p-1)
         *     exponent2         INTEGER,  -- d mod (q-1)
         *     coefficient       INTEGER,  -- (inverse of q) mod p
         *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
         * }
         *
         * RSA private key, the OID is 1.2.840.113549.1.1.1 &
         * RSAPrivateKey representing the PrivateKey key data
         * bitstring is present.
         */

        // Encrypted Private Key (PKCS#8) Tags:
        $beg_enc_pk_pri_text = '-----BEGIN ENCRYPTED PRIVATE KEY-----';
        $beg_enc_pk_pri_text = '-----END ENCRYPTED PRIVATE KEY-----';

        /**
         * Encrypted Private Key (PKCS#8) DER Structure:
         *
         * EncryptedPrivateKeyInfo ::= SEQUENCE {
         *     encryptionAlgorithm  EncryptionAlgorithmIdentifier,
         *     encryptedData        EncryptedData
         * }
         *
         * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
         * EncryptedData ::= OCTET STRING
         *
         * EncryptedData OCTET STRING is a PKCS#8 PrivateKeyInfo.
         */

        // Elliptic Curve Private Key Tags:
        $beg_ec_pri_text = '-----BEGIN EC PRIVATE KEY-----';
        $end_ec_pri_text = '-----END EC PRIVATE KEY-----';

        /**
         * Elliptic Curve Private Key Structure:
         * TODO - fill this in.
         */

        // Elliptic Curve Public Key Tags:
        $beg_ec_pub_text = '-----BEGIN EC PUBLIC KEY-----';
        $end_ec_pub_text = '-----END EC PUBLIC KEY-----';

        /**
         * Elliptic Curve Public Key Structure:
         * TODO - fill this in.
         */

        $decoded     = '';
        $pemstruct = array();

        // TODO: Update this for more key tags:
        // $pem_data = str_ireplace($beg_ec_text, '', $pem_data);
        // $pem_data = str_ireplace($end_ec_text, '', $pem_data);
        $pem_data = str_ireplace("\r",         '', trim($pem_data));
        $pem_data = str_ireplace("\n",         '', trim($pem_data));
        $pem_data = str_ireplace(' ',          '', trim($pem_data));

        $decoded = bin2hex(base64_decode($pem_data));

        $pemstruct = array(
                             'oct_sec_val'  => substr($decoded, 14, 64),
                             'obj_id_val'   => substr($decoded, 86, 10),
                             'bit_str_val'  => substr($decoded, 106),
                       );

        $private_key = $pemstruct['oct_sec_val'];
        $public_key  = $pemstruct['bit_str_val'];
        $object_id   = $pemstruct['obj_id_val'];

        return array(
                     'private_key' => $pemstruct['oct_sec_val'],
                     'public_key'  => $pemstruct['bit_str_val'],
                     'object_id'   => $pemstruct['obj_id_val']
               );
    }

    /**
     * Encodes keypair data to PEM format.
     *
     * @param  array  $keypair The keypair info.
     * @return string          The data to decode.
     * @throws \Exception
     */
    public function pemEncode($keypair = null)
    {
    	if (empty($keypair) || (is_array($keypair) && (strlen($keypair[0]) < 64 || strlen($keypair[1]) < 128))) {
    		throw new \Exception('Invalid or corrupt keypair provided. Cannot decode the supplied PEM data.');
    	}

    	$dec         = '';
    	$byte        = '';
    	$seq         = '';
    	$decoded     = '';
    	$beg_ec_text = '';
    	$end_ec_text = '';
    	$ecpemstruct = array();
    	$digits      = array();

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

    	$beg_ec_text = '-----BEGIN EC PRIVATE KEY-----';
    	$end_ec_text = '-----END EC PRIVATE KEY-----';
    	$dec         = trim(implode($ecpemstruct));

    	if (strlen($dec) < 230) {
    		throw new \Exception('Invalid or corrupt keypair provided. Cannot encode the supplied data.');
    	}

    	$dec = $this->decodeHex('0x' . $dec);

    	while (gmp_cmp($dec, '0') > 0) {
    		$dv   = gmp_div($dec, '256');
    		$rem  = gmp_strval(gmp_mod($dec, '256'));
    		$dec  = $dv;
    		$byte = $byte . $digits[$rem];
    	}

    	return $beg_ec_text . "\r\n" . chunk_split(base64_encode(strrev($byte)), 64) . $end_ec_text;
    }

    /**
     * Checks if the required extensions are loaded.
     *
     * @throws \Exception
     */
    private function checkExtensions()
    {
        if (!extension_loaded('gmp')) {
            throw new \Exception('This class requires the GMP math extension for PHP. Please install this extension or ask your system administrator to install it for you.');
        }
    }
}
