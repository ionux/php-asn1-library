<?php
/**
 * These tests are a work in progress. If you have ideas
 * for additional or improved test cases, please submit
 * a pull request.
 *
 * Thanks,
 * Rich <rich@richmorgan.me>
 */

namespace Tests;

use \ASN1\Pem;

class PemTest extends \PHPUnit_Framework_TestCase
{
    public function testPemDecode()
    {
    	$data = '-----BEGIN EC PRIVATE KEY-----' . "\r\n" .
                'MHQCAQEEICg7E4NN53YkaWuAwpoqjfAofjzKI7Jq1f532dX+0O6QoAcGBSuBBAAK' . "\r\n" .
                'oUQDQgAEjZcNa6Kdz6GQwXcUD9iJ+t1tJZCx7hpqBuJV2/IrQBfue8jh8H7Q/4vX' . "\r\n" .
                'fAArmNMaGotTpjdnymWlMfszzXJhlw==' . "\r\n" .
    	        '-----END EC PRIVATE KEY-----';

    	$private_key = '85404c428460c1d00804041080a0ec4e0d379dd891a5ae030a68aa37c0a1f8f3';
    	$public_key  = '1c1814ae0410002a85100d080012365c35ae8a773e864305dc503f6227eb75b49642c7b869a81b89576fc8ad005fb9ef2387c1fb43fe2f5df000ae634c686a2d4e98dd9f299694c7eccf35c9865c043431023d121501310a11';

    	$pem = new Pem();
    	$this->assertNotNull($pem);

    	$pkey = $pem->pemDecode($data);
    	$this->assertNotNull($pkey);

    	// Ensure it's an array
    	$this->assertInternalType('array', $pkey);

    	// Ensure the private key matches the expected value
    	$this->assertEquals($private_key, $pkey['private_key']);

    	// Ensure the public key matches the expected value
    	$this->assertEquals($public_key, $pkey['public_key']);
    }

    public function testPemEncode()
    {
    	$data = '-----BEGIN EC PRIVATE KEY-----' . "\r\n" .
                'MHQCAQEEICg7E4NN53YkaWuAwpoqjfAofjzKI7Jq1f532dX+0O6QoAcGBSuBBAAK' . "\r\n" .
                'oUQDQgAEjZcNa6Kdz6GQwXcUD9iJ+t1tJZCx7hpqBuJV2/IrQBfue8jh8H7Q/4vX' . "\r\n" .
                'fAArmNMaGotTpjdnymWlMfszzXJhlw==' . "\r\n" .
    	        '-----END EC PRIVATE KEY-----';

    	$private_key = '283b13834de77624696b80c29a2a8df0287e3cca23b26ad5fe77d9d5fed0ee90';
    	$public_key  = '048d970d6ba29dcfa190c177140fd889fadd6d2590b1ee1a6a06e255dbf22b4017ee7bc8e1f07ed0ff8bd77c002b98d31a1a8b53a63767ca65a531fb33cd726197';

    	$keypair = array($private_key, $public_key);

    	$pem = new Pem();
    	$this->assertNotNull($pem);

    	$pemdata = $pem->pemEncode($keypair);
    	$this->assertNotNull($pemdata);

    	// Ensure it's a string
    	$this->assertInternalType('string', $pemdata);

    	// Ensure the PEM-encoded data matches the expected value
    	$this->assertEquals($data, $pemdata);
    }
}
