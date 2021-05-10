<?php

namespace LaminasTest\Xml;

use Laminas\Xml\Exception;
use Laminas\Xml\Exception\RuntimeException;
use Laminas\Xml\Security;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * @group ZF2015-06
 */
class MultibyteTest extends TestCase
{
    /**
     * @psalm-return array<array-key, array{0: string, 1: string, 2: int}>
     */
    public function multibyteEncodings(): array
    {
        return [
            'UTF-16LE' => ['UTF-16LE', pack('CC', 0xff, 0xfe), 3],
            'UTF-16BE' => ['UTF-16BE', pack('CC', 0xfe, 0xff), 3],
            'UTF-32LE' => ['UTF-32LE', pack('CCCC', 0xff, 0xfe, 0x00, 0x00), 4],
            'UTF-32BE' => ['UTF-32BE', pack('CCCC', 0x00, 0x00, 0xfe, 0xff), 4],
        ];
    }

    public function getXmlWithXXE(): string
    {
        return <<<XML
            <?xml version="1.0" encoding="{ENCODING}"?>
            <!DOCTYPE methodCall [
                <!ENTITY pocdata SYSTEM "file:///etc/passwd">
            ]>
            <methodCall>
                <methodName>retrieved: &pocdata;</methodName>
            </methodCall>
            XML;
    }

    /**
     * Invoke Laminas\Xml\Security::heuristicScan with the provided XML.
     *
     * @throws Exception\RuntimeException
     */
    public function invokeHeuristicScan(string $xml): void
    {
        $r = new ReflectionMethod(Security::class, 'heuristicScan');
        $r->setAccessible(true);
        $r->invoke(null, $xml);
    }

    /**
     * @dataProvider multibyteEncodings
     * @group heuristicDetection
     */
    public function testDetectsMultibyteXXEVectorsUnderFPMWithEncodedStringMissingBOM(
        string $encoding,
        string $bom,
        int $bomLength
    ): void {
        $xml = $this->getXmlWithXXE();
        $xml = str_replace('{ENCODING}', $encoding, $xml);
        $xml = iconv('UTF-8', $encoding, $xml);
        $this->assertNotSame(0, strncmp($xml, $bom, $bomLength));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ENTITY');
        $this->invokeHeuristicScan($xml);
    }

    /**
     * @dataProvider multibyteEncodings
     */
    public function testDetectsMultibyteXXEVectorsUnderFPMWithEncodedStringUsingBOM(
        string $encoding,
        string $bom
    ): void {
        $xml  = $this->getXmlWithXXE();
        $xml  = str_replace('{ENCODING}', $encoding, $xml);
        $orig = iconv('UTF-8', $encoding, $xml);
        $xml  = $bom . $orig;
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ENTITY');
        $this->invokeHeuristicScan($xml);
    }

    public function getXmlWithoutXXE(): string
    {
        return <<<XML
            <?xml version="1.0" encoding="{ENCODING}"?>
            <methodCall>
                <methodName>retrieved: &pocdata;</methodName>
            </methodCall>
            XML;
    }

    /**
     * @dataProvider multibyteEncodings
     */
    public function testDoesNotFlagValidMultibyteXmlAsInvalidUnderFPM(string $encoding): void
    {
        $xml = $this->getXmlWithoutXXE();
        $xml = str_replace('{ENCODING}', $encoding, $xml);
        $xml = iconv('UTF-8', $encoding, $xml);
        try {
            $result = $this->invokeHeuristicScan($xml);
            $this->assertNull($result);
        } catch (\Exception $e) {
            $this->fail('Security scan raised exception when it should not have');
        }
    }

    /**
     * @dataProvider multibyteEncodings
     * @group mixedEncoding
     */
    public function testDetectsXXEWhenXMLDocumentEncodingDiffersFromFileEncoding(
        string $encoding,
        string $bom
    ): void {
        $xml = $this->getXmlWithXXE();
        $xml = str_replace('{ENCODING}', 'UTF-8', $xml);
        $xml = iconv('UTF-8', $encoding, $xml);
        $xml = $bom . $xml;
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('ENTITY');
        $this->invokeHeuristicScan($xml);
    }
}
