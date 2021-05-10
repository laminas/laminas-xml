<?php

namespace LaminasTest\Xml;

use DOMDocument;
use Laminas\Xml\Exception;
use Laminas\Xml\Security as XmlSecurity;
use PHPUnit\Framework\TestCase;
use SimpleXMLElement;

class SecurityTest extends TestCase
{
    /**
     * @expectedException Laminas\Xml\Exception\RuntimeException
     */
    public function testScanForXEE(): void
    {
        $xml = <<<XML
            <?xml version="1.0"?>
            <!DOCTYPE results [<!ENTITY harmless "completely harmless">]>
            <results>
                <result>This result is &harmless;</result>
            </results>
            XML;

        $this->expectException('Laminas\Xml\Exception\RuntimeException');
        XmlSecurity::scan($xml);
    }

    public function testScanForXXE(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'laminas-xml_Security');
        file_put_contents($file, 'This is a remote content!');
        $xml = <<<XML
            <?xml version="1.0"?>
            <!DOCTYPE root
            [
                <!ENTITY foo SYSTEM "file://$file">
            ]>
            <results>
                <result>&foo;</result>
            </results>
            XML;

        try {
            XmlSecurity::scan($xml);
        } catch (Exception\RuntimeException $e) {
            unlink($file);
            return;
        }
        $this->fail('An expected exception has not been raised.');
    }

    public function testScanSimpleXmlResult(): void
    {
        $result = XmlSecurity::scan($this->getXml());
        $this->assertTrue($result instanceof SimpleXMLElement);
        $this->assertEquals($result->result, 'test');
    }

    public function testScanDom(): void
    {
        $dom = new DOMDocument('1.0');
        $result = XmlSecurity::scan($this->getXml(), $dom);
        $this->assertTrue($result instanceof DOMDocument);
        $node = $result->getElementsByTagName('result')->item(0);
        $this->assertEquals($node->nodeValue, 'test');
    }

    public function testScanDomHTML(): void
    {
        // LIBXML_HTML_NODEFDTD and LIBXML_HTML_NOIMPLIED require libxml 2.7.8+
        // http://php.net/manual/de/libxml.constants.php
        if (version_compare(LIBXML_DOTTED_VERSION, '2.7.8', '<')) {
            $this->markTestSkipped(
                'libxml 2.7.8+ required but found ' . LIBXML_DOTTED_VERSION
            );
        }

        $dom = new DOMDocument('1.0');
        $html = <<<HTML
            <p>a simple test</p>
            HTML;
        $constants = LIBXML_HTML_NODEFDTD | LIBXML_HTML_NOIMPLIED;
        $result = XmlSecurity::scanHtml($html, $dom, $constants);
        $this->assertTrue($result instanceof DOMDocument);
        $this->assertEquals($html, trim($result->saveHtml()));
    }

    public function testScanInvalidXml(): void
    {
        $xml = <<<XML
            <foo>test</bar>
            XML;

        $result = XmlSecurity::scan($xml);
        $this->assertFalse($result);
    }

    public function testScanInvalidXmlDom(): void
    {
        $xml = <<<XML
            <foo>test</bar>
            XML;

        $dom = new DOMDocument('1.0');
        $result = XmlSecurity::scan($xml, $dom);
        $this->assertFalse($result);
    }

    public function testScanFile(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'laminas-xml_Security');
        file_put_contents($file, $this->getXml());

        $result = XmlSecurity::scanFile($file);
        $this->assertTrue($result instanceof SimpleXMLElement);
        $this->assertEquals($result->result, 'test');
        unlink($file);
    }

    public function testScanXmlWithDTD(): void
    {
        $xml = <<<XML
            <?xml version="1.0"?>
            <!DOCTYPE results [
                <!ELEMENT results (result+)>
                <!ELEMENT result (#PCDATA)>
            ]>
            <results>
                <result>test</result>
            </results>
            XML;

        $dom = new DOMDocument('1.0');
        $result = XmlSecurity::scan($xml, $dom);
        $this->assertTrue($result instanceof DOMDocument);
        $this->assertTrue($result->validate());
    }

    protected function getXml(): string
    {
        return <<<XML
            <?xml version="1.0"?>
            <results>
                <result>test</result>
            </results>
            XML;
    }
}
