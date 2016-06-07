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

use \ANS1\Pem;
use \ASN1\OID;

class PemTest extends \PHPUnit_Framework_TestCase
{
    public function testPemDecode()
    {
    	$data = '-----BEGIN EC PRIVATE KEY-----' . "\r\n" .
                'MHQCAQEEICg7E4NN53YkaWuAwpoqjfAofjzKI7Jq1f532dX+0O6QoAcGBSuBBAAK' . "\r\n" .
                'oUQDQgAEjZcNa6Kdz6GQwXcUD9iJ+t1tJZCx7hpqBuJV2/IrQBfue8jh8H7Q/4vX' . "\r\n" .
                'fAArmNMaGotTpjdnymWlMfszzXJhlw==' . "\r\n" .
    	        '-----END EC PRIVATE KEY-----';

    	$private_key = '283b13834de77624696b80c29a2a8df0287e3cca23b26ad5fe77d9d5fed0ee90';
    	$public_key  = '048d970d6ba29dcfa190c177140fd889fadd6d2590b1ee1a6a06e255dbf22b4017ee7bc8e1f07ed0ff8bd77c002b98d31a1a8b53a63767ca65a531fb33cd726197';

    	$pem = new Pem();
    	$this->assertNotNull($pem);

    	$pem = $pkey->pemDecode($data);
    	$this->assertNotNull($pem);

    	// Ensure it's an array
    	$this->assertInternalType('array', $pem);

    	// Ensure the private key matches the expected value
    	$this->assertEquals($private_key, $pem['private_key']);

    	// Ensure the public key matches the expected value
    	$this->assertEquals($public_key, $pem['public_key']);
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
